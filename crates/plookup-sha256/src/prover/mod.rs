#![allow(non_snake_case)]

use std::time::Instant;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use ark_ec::PairingEngine;
use ark_ff::{BigInteger, ToBytes, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_poly_commit::kzg10::Commitment;
use ark_poly_commit::{LCTerm, LinearCombination};
use ark_std::{borrow::Borrow, cfg_iter_mut, format, ops::Mul, rand::RngCore, vec, vec::Vec};
use sha2::{Digest, Sha256};

mod prover_key;
pub use prover_key::*;

use crate::composer::ComposerConfig;
use crate::kzg10::PCKey;
use crate::proof::Proof;
use crate::prover::widget::{MiMCWidget, PubMatchWidget, SubStringWidget};
use crate::transcript::TranscriptLibrary;
use crate::utils::interpolate_and_coset_fft;
use crate::{
    blind_and_coset_fft, blind_t, gen_verify_comms_labels, gen_verify_open_zeta_labels,
    gen_verify_open_zeta_omega_labels, padding_and_interpolate, Composer, Domain, Error, Field,
    Map,
};

mod widget;
use widget::{ArithmeticWidget, LookupWidget, PermutationWidget, RangeWidget, Widget};

pub struct Prover<F: Field, D: Domain<F>, E: PairingEngine> {
    domain_values: Map<String, Vec<F>>, //already padded
    coset_values: Map<String, Vec<F>>,  //coset fft
    polynomials: Map<String, DensePolynomial<F>>,

    challenges: Map<String, F>,
    pub evaluations: Map<String, F>,
    pub commitments: Map<String, Commitment<E>>,

    pub domain: D,
    pub coset: D,
    pub program_width: usize,
    
    pub composer_config: ComposerConfig,
}

impl<'a, F: Field, D: Domain<F>, E: PairingEngine> Prover<F, D, E> {
    pub fn domain_size(&self) -> usize {
        self.domain.size()
    }

    pub fn coset_size(&self) -> usize {
        self.coset.size()
    }

    // Preprocessing vectors into polynomials, etc
    pub fn insert(&mut self, label: &str, domain_values: Vec<F>) {
        let (domain_values, coset_values, polynomial) =
            interpolate_and_coset_fft(domain_values, self.domain, self.coset);

        self.domain_values.insert(label.to_string(), domain_values);
        self.coset_values.insert(label.to_string(), coset_values);
        self.polynomials.insert(label.to_string(), polynomial);
    }

    // will blind the poly according to open_num
    pub fn insert_with_blind<R: RngCore>(
        &mut self,
        label: &str,
        domain_values: Vec<F>,
        open_num: usize,
        rng: &mut R,
    ) {
        let (domainvalues, poly) = padding_and_interpolate(domain_values, self.domain);
        let (coset, blindpoly) = blind_and_coset_fft(poly, self.domain, self.coset, open_num, rng);

        self.domain_values.insert(label.to_string(), domainvalues);
        self.coset_values.insert(label.to_string(), coset);
        self.polynomials.insert(label.to_string(), blindpoly);
    }

    pub fn add_polynomial(&mut self, label: &str, polynomial: DensePolynomial<F>) {
        self.polynomials.insert(label.to_string(), polynomial);
    }

    pub fn add_challenge(&mut self, label: &str, value: F) {
        assert!(!self.challenges.contains_key(label));
        self.challenges.insert(label.to_string(), value);
    }

    pub fn get_challenge(&self, l: &str) -> Result<F, Error> {
        self.challenges
            .get(l)
            .cloned()
            .ok_or(Error::MissingElement(l.to_string()))
    }

    pub fn domain_values(&self) -> &Map<String, Vec<F>> {
        &self.domain_values
    }

    pub fn coset_values(&self) -> &Map<String, Vec<F>> {
        &self.coset_values
    }

    pub fn remove_coset_values(&mut self, key: &str) {
        self.coset_values.remove(key);
    }

    pub fn get_coset_values(&self, label: &str) -> Result<&[F], Error> {
        match self.coset_values.get(label) {
            None => Err(Error::MissingElement(format!(
                "missing coset values: {}",
                label
            ))),
            Some(v) => Ok(v),
        }
    }

    pub fn polynomials(&self) -> &Map<String, DensePolynomial<F>> {
        &self.polynomials
    }

    /// get the value of a polynomial at a given point
    pub fn evaluate(&mut self, poly_label: &str, point_label: &str) -> Result<F, Error> {
        let label = format!("{}_{}", poly_label, point_label);
        match self.evaluations.get(&label) {
            // cache
            Some(v) => Ok(*v),
            None => {
                let poly = self
                    .polynomials
                    .get(poly_label)
                    .ok_or(Error::MissingElement(poly_label.to_string()))?;
                let point = self
                    .challenges
                    .get(point_label)
                    .ok_or(Error::MissingElement(point_label.to_string()))?;
                //do cal. then save
                let value = poly.evaluate(point);
                self.evaluations.insert(label, value);

                Ok(value)
            }
        }
    }

    /// get the value of a LinearCombination at a given point
    pub fn evaluate_linear_combination(
        &mut self,
        lc: &LinearCombination<F>,
        point_label: &str,
    ) -> Result<F, Error> {
        let label = format!("{}_{}", lc.label, point_label);
        match self.evaluations.get(&label) {
            Some(value) => Ok(*value),
            None => {
                let point = self
                    .challenges
                    .get(point_label)
                    .ok_or(Error::MissingElement(point_label.to_string()))?;
                let value = evaluate_linear_combination(lc, &self.polynomials, point)?;
                self.evaluations.insert(label, value);
                Ok(value)
            }
        }
    }
}

impl<'a, F: Field, D: Domain<F>, E: PairingEngine> Prover<F, D, E> {
    pub fn new(prover_key: ProverKey<F, D>) -> Self {
        Self {
            domain_values: prover_key.domain_values(),
            coset_values: prover_key.coset_values(),
            polynomials: prover_key.polynomials(),
            challenges: Map::new(),
            evaluations: Map::new(),
            commitments: Map::new(),
            domain: prover_key.domain,
            coset: prover_key.coset,
            program_width: prover_key.program_width,
            composer_config: prover_key.composer_config,
        }
    }

    /// if already have, no need "init_comms"
    pub fn insert_verifier_comms(&mut self, vcomms: &Vec<Commitment<E>>) {
        let labels = gen_verify_comms_labels(
            self.program_width,
            self.composer_config,
        );

        for (str, comm) in labels.iter().zip(vcomms) {
            self.commitments.insert(str.to_string(), comm.clone());
        }
    }

    /// return the verifier_commitments
    pub fn init_comms(&mut self, pckey: &PCKey<E>) -> Vec<Commitment<E>> {
        let mut res = vec![];

        let polys = self.polynomials();
        let mut commitments = Map::new();
        let labels = gen_verify_comms_labels(
            self.program_width,
            self.composer_config,
        );
        for str in labels {
            let v = &polys[str.as_str()];
            let tmp = pckey.commit_one(v);

            res.push(tmp.clone());
            commitments.insert(str.to_string(), tmp);
        }

        self.commitments = commitments;
        res
    }

    /// PLONK prove. inputs: circuit, polynomial_commitment_key, rng for blind
    pub fn prove<R: RngCore>(
        &mut self,
        cs: &mut Composer<F>,
        pckey: &PCKey<E>,
        rng: &mut R,
    ) -> Result<Proof<F, E>, Error> {
        // now we must contain lookup
        assert!(self.composer_config.enable_lookup);
        let public_input = cs.compute_public_input();

        // P and V must keep the same order
        let mut widgets: Vec<Box<dyn Widget<F, D, E, R>>> = vec![
            Box::new(ArithmeticWidget::new(cs.program_width)),
            Box::new(PermutationWidget::new(cs.program_width)),
        ];
        if self.composer_config.enable_lookup {
            widgets.push(Box::new(LookupWidget::new(cs.program_width)));
        }
        if self.composer_config.enable_range {
            widgets.push(Box::new(RangeWidget::new(cs.program_width)));
        }
        if self.composer_config.enable_private_substring {
            widgets.push(Box::new(SubStringWidget::new(cs.program_width)));
        }
        if self.composer_config.enable_pubmatch {
            widgets.push(Box::new(PubMatchWidget::new(cs.program_width)));
        }
        if self.composer_config.enable_mimc {
            widgets.push(Box::new(MiMCWidget::new(cs.program_width)));
        }

        let mut z_labels = vec!["z".to_string(), "z_lookup".to_string()];
        if self.composer_config.enable_private_substring {
            z_labels.push("z_substring".to_string());
        }

        let mut trans = TranscriptLibrary::new();
        log::trace!("prove start:");
        let start = Instant::now();
        log::trace!("initializing...");

        // sha256 SRS, put into the transcript
        let srshash = pckey.sha256_of_srs();
        trans.update_with_u256(srshash);

        let pi_num = public_input.len() as u64;
        let v0_domainsize = self.domain_size() as u128;
        let omega = self.domain.generator();
        let mut vcomms = vec![];
        let mut g2xbytes = vec![];

        let verify_comms_labels = gen_verify_comms_labels(
            self.program_width,
            self.composer_config,
        );
        for str in &verify_comms_labels {
            let comm = self.commitments[str];
            let tmp = comm.0;
            let mut bytes = [0u8; 64];
            let _ = tmp.write(bytes.as_mut());
            let mut x = [0u8; 32];
            for j in 0..32 {
                x[32 - j - 1] = bytes[j];
            }
            let mut y = [0u8; 32];
            for j in 32..64 {
                y[64 - j - 1] = bytes[j];
            }
            if tmp.is_zero() {
                vcomms.push(x);
                vcomms.push(x);
            } else {
                vcomms.push(x);
                vcomms.push(y);
            }
        }
        let g2x = pckey.vk.beta_h;
        let mut bytes = [0u8; 128];
        let _ = g2x.write(bytes.as_mut());
        let mut xc0 = [0u8; 32];
        for j in 0..32 {
            xc0[32 - j - 1] = bytes[j];
        }
        let mut xc1 = [0u8; 32];
        for j in 32..64 {
            xc1[64 - j - 1] = bytes[j];
        }
        let mut yc0 = [0u8; 32];
        for j in 64..96 {
            yc0[96 - j - 1] = bytes[j];
        }
        let mut yc1 = [0u8; 32];
        for j in 96..128 {
            yc1[128 - j - 1] = bytes[j];
        }
        g2xbytes.push(xc0);
        g2xbytes.push(xc1);
        g2xbytes.push(yc0);
        g2xbytes.push(yc1);

        let mut prehasher = Sha256::new();
        prehasher.update(pi_num.to_be_bytes());
        prehasher.update(v0_domainsize.to_be_bytes());
        prehasher.update(omega.into_repr().to_bytes_be());
        for v in vcomms {
            prehasher.update(v);
        }
        for v in g2xbytes {
            prehasher.update(v);
        }
        let result = prehasher.finalize();
        trans.update_with_u256(result);

        for pi in &public_input {
            trans.update_with_fr(pi);
        }

        self.insert("pi", public_input.to_vec());
        //witnesses, and s0 s1 s2 s3 s4...
        let (wires, swires) = cs.compute_wire_values()?;

        for i in 0..self.program_width {
            let label = format!("w_{}", i);
            let open_num =
                if i == 0 || (self.composer_config.enable_private_substring && ((i == 1) || (i == 2) || (i == 3))) {
                    2
                } else {
                    1
                };
            self.insert_with_blind(&label, wires[&label].clone(), open_num, rng);
        }

        for (k, mut w) in swires.into_iter() {
            let zeros = vec![F::zero(); self.domain.size() - w.len()];
            w.extend(zeros);
            self.domain_values.insert(k, w);
        }
        log::trace!("initialize done");

        let w_poly: Vec<_> = (0..self.program_width)
            .into_iter()
            .map(|i| {
                let str = format!("w_{}", i);
                self.polynomials()[&str].clone()
            })
            .collect();
        let w_comms = pckey.commit_vec(&w_poly);

        for wi in &w_comms {
            trans.update_with_g1::<E>(&wi.0);
        }

        log::trace!("first round..."); //only lookup
        let eta = trans.generate_challenge::<F>();
        self.add_challenge("eta", eta);
        for w in widgets.iter() {
            w.compute_oracles(1, self, rng)?;
        }
        log::trace!("first round done");

        let polys = self.polynomials();
        let s_poly = &polys["s"];
        let s_comm = pckey.commit_one(s_poly);
        self.commitments.insert("s".to_string(), s_comm);
        trans.update_with_g1::<E>(&s_comm.0);

        log::trace!("second_round...");
        let beta = trans.generate_challenge::<F>();
        let gamma = trans.generate_challenge::<F>();
        self.add_challenge("beta", beta);
        self.add_challenge("gamma", gamma);
        for w in widgets.iter() {
            w.compute_oracles(2, self, rng)?;
        }
        log::trace!("second_round done");

        for str in &z_labels {
            let z_poly = &self.polynomials()[str];
            let z_comm = pckey.commit_one(z_poly);
            self.commitments.insert(str.to_string(), z_comm);
            trans.update_with_g1::<E>(&z_comm.0);
        }

        log::trace!("third round...");
        let alpha = trans.generate_challenge::<F>();
        self.add_challenge("alpha", alpha);
        let t = {
            let mut combinator = F::one();

            let mut quotient = vec![F::zero(); self.coset_size()];
            for w in widgets.iter() {
                w.compute_quotient_contribution(self, &mut combinator, &mut quotient)?;
            }

            let vi = self.get_coset_values("vi")?;
            cfg_iter_mut!(quotient).zip(vi).for_each(|(q, v)| *q *= v);
            let t = DensePolynomial::from_coefficients_vec(self.coset.coset_ifft(&quotient));

            t
        };

        // free mem
        self.coset_values = Map::new();

        let mut t_chunks = split(t, self.domain_size());
        log::trace!("t_chunks.len() {}", t_chunks.len());
        while t_chunks.len() < self.program_width {
            //not always program_width. it depends on the 'max degree' which custom gates need
            t_chunks.push(DensePolynomial::zero());
        }
        // high probability because of blind
        if t_chunks.len() > self.program_width {
            //put the extra in the last
            let mut extra = t_chunks.pop().unwrap();
            log::trace!("t extra n {}", extra.coeffs.len());
            let mut last = t_chunks.pop().unwrap().coeffs.clone();
            last.append(&mut extra.coeffs);
            t_chunks.push(DensePolynomial::from_coefficients_vec(last));
        }

        // blind t
        let t_chunks = blind_t(t_chunks, self.domain, rng);

        for (i, t) in t_chunks.into_iter().enumerate() {
            self.add_polynomial(&format!("t_{}", i), t);
        }
        log::trace!("third round done");

        let t_poly: Vec<_> = (0..self.program_width)
            .into_iter()
            .map(|i| {
                let str = format!("t_{}", i);
                self.polynomials()[&str].clone()
            })
            .collect();
        let t_comms = pckey.commit_vec(&t_poly);
        for ti in &t_comms {
            trans.update_with_g1::<E>(&ti.0);
        }

        log::trace!("forth round...");
        let zeta = trans.generate_challenge::<F>();
        self.add_challenge("zeta", zeta);
        self.add_challenge("zeta_omega", zeta * self.domain.generator());
        let (r, r_complement) = {
            let mut r = LinearCombination::<F>::empty("r");
            let mut r_complement = F::zero();
            let mut combinator = F::one();

            for w in widgets.iter() {
                let (w_r, w_complement) = &w.compute_linear_contribution(self, &mut combinator)?;

                r += w_r;
                r_complement += w_complement;
            }

            (r, r_complement)
        };

        let r_poly = {
            let mut acc = DensePolynomial::zero();
            for (coeff, term) in r.iter() {
                //term_label: label for a polynomial in this(r) LC
                acc = if let LCTerm::PolyLabel(term_label) = term {
                    let polynomial = self
                        .polynomials
                        .get(term_label)
                        .ok_or(Error::MissingElement(format!(
                            "polynomial {} for linear combination {}",
                            term_label, r.label
                        )))?
                        .borrow();
                    acc + polynomial.mul(&DensePolynomial::from_coefficients_vec(vec![*coeff]))
                } else {
                    // otherwise should be const term
                    assert!(term.is_one());
                    acc + DensePolynomial::from_coefficients_vec(vec![*coeff])
                }
            }
            acc
        };
        self.add_polynomial("r", r_poly);
        let r_zeta = self.evaluate("r", "zeta")?;

        let zeta_n = zeta.pow(&[self.domain_size() as u64]);

        let mut tmp = zeta_n;
        let mut t_LC_terms = vec![(F::one(), format!("t_{}", 0))];
        for i in 1..self.program_width {
            let str = format!("t_{}", i);
            t_LC_terms.push((tmp, str));

            tmp *= zeta_n;
        }
        let t = { LinearCombination::<F>::new("t", t_LC_terms) };

        let t_split_poly = {
            let mut acc = DensePolynomial::zero();
            for (coeff, term) in t.iter() {
                acc = if let LCTerm::PolyLabel(term_label) = term {
                    let polynomial = self
                        .polynomials
                        .get(term_label)
                        .ok_or(Error::MissingElement(format!(
                            "polynomial {} for linear combination {}",
                            term_label, t.label
                        )))?
                        .borrow();
                    acc + polynomial.mul(&DensePolynomial::from_coefficients_vec(vec![*coeff]))
                } else {
                    assert!(term.is_one());
                    acc + DensePolynomial::from_coefficients_vec(vec![*coeff])
                }
            }
            acc
        };
        self.add_polynomial("t4t", t_split_poly);
        let t_zeta = self.evaluate("t4t", "zeta")?;
        log::trace!("forth round done");

        let verify_open_zeta_labels =
            gen_verify_open_zeta_labels(self.program_width, self.composer_config.enable_lookup);
        let verify_open_zeta_omega_labels =
            gen_verify_open_zeta_omega_labels(
                self.composer_config,
            );
        for str in &verify_open_zeta_labels {
            let tmp = self.evaluate(str.as_str(), "zeta")?;
            trans.update_with_fr(&tmp);
        }
        for str in &verify_open_zeta_omega_labels {
            let tmp = self.evaluate(str.as_str(), "zeta_omega")?;
            trans.update_with_fr(&tmp);
        }
        let v = trans.generate_challenge::<F>();
        self.add_challenge("v", v);
        // let u = trans.generate_challenge::<F>();
        // self.add_challenge("u", u);

        // NOT the W(X). only numerator.
        // compute_opening_proof_w_poly
        let Wz_numer = {
            let mut Wz_numer = DensePolynomial::zero();
            let mut comb = F::one();
            for str in &verify_open_zeta_labels {
                Wz_numer = Wz_numer + self.polynomials[str.as_str()].mul(comb);
                comb = comb * v;
            }

            Wz_numer
        };
        let Wz_pi = pckey.open_one(&Wz_numer, zeta);

        // NOT the Wz(X). only numerator.
        // compute_opening_proof_w_poly
        let Wzw_numer = {
            let mut Wzw_numer = DensePolynomial::zero();
            let mut comb = F::one();
            for str in &verify_open_zeta_omega_labels {
                Wzw_numer = Wzw_numer + self.polynomials[str.as_str()].mul(comb);
                comb = comb * v;
            }

            Wzw_numer
        };
        let Wzw_pi = pckey.open_one(&Wzw_numer, zeta * self.domain.generator());

        trans.update_with_g1::<E>(&Wz_pi.0);
        trans.update_with_g1::<E>(&Wzw_pi.0);
        let u = trans.generate_challenge::<F>();
        self.add_challenge("u", u);

        log::trace!("check equality...");
        let lhs = {
            let v_zeta = self.domain.evaluate_vanishing_polynomial(zeta);
            t_zeta * v_zeta
        };
        let rhs = {
            let pi_zeta = self.evaluate("pi", "zeta")?;

            r_zeta - r_complement - pi_zeta
        };

        assert_eq!(lhs, rhs, "prover equality check");
        log::trace!("check equality done");

        // gen proof
        let mut proof_evals = vec![];
        for str in &verify_open_zeta_labels {
            proof_evals.push(self.evaluate(str.as_str(), "zeta")?)
        }
        let mut proof_evals_alt = vec![];
        for str in &verify_open_zeta_omega_labels {
            proof_evals_alt.push(self.evaluate(str.as_str(), "zeta_omega")?)
        }

        let mut proof_comms1 = vec![];
        for c in w_comms {
            proof_comms1.push(c);
        }

        let mut proof_comms3 = vec![];
        for str in &z_labels {
            proof_comms3.push(self.commitments[str]);
        }

        let mut proof_comms4 = vec![];
        for c in t_comms {
            proof_comms4.push(c);
        }

        let proof = Proof::<F, E> {
            commitments1: proof_comms1,
            commitment2: s_comm,
            commitments3: proof_comms3,
            commitments4: proof_comms4,
            evaluations: proof_evals,
            evaluations_alt_point: proof_evals_alt,
            Wz_pi: Wz_pi,
            Wzw_pi: Wzw_pi,
        };

        log::trace!("prove time cost: {:?} ms", start.elapsed().as_millis()); // ms
        Ok(proof)
    }
}

fn split<F: Field>(poly: DensePolynomial<F>, chunk_size: usize) -> Vec<DensePolynomial<F>> {
    let mut chunks = Vec::new();

    let mut coeffs = poly.coeffs.into_iter().peekable();
    while coeffs.peek().is_some() {
        let chunk: Vec<_> = coeffs.by_ref().take(chunk_size).collect();
        chunks.push(DensePolynomial::from_coefficients_vec(chunk.to_vec()));
    }

    chunks
}

//cal the poly, then evaluate
fn evaluate_linear_combination<F: Field>(
    lc: &LinearCombination<F>,
    polynomials: &Map<String, DensePolynomial<F>>,
    point: &F,
) -> Result<F, Error> {
    let mut acc = DensePolynomial::zero();
    for (coeff, term) in lc.iter() {
        acc = if let LCTerm::PolyLabel(term_label) = term {
            let polynomial = polynomials
                .get(term_label)
                .ok_or(Error::MissingElement(format!(
                    "polynomial {} for linear combination {}",
                    term_label, lc.label
                )))?
                .borrow();
            acc + polynomial.mul(&DensePolynomial::from_coefficients_vec(vec![*coeff]))
        } else {
            assert!(term.is_one());
            acc + DensePolynomial::from_coefficients_vec(vec![*coeff])
        }
    }

    Ok(acc.evaluate(point))
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]
    use ark_bn254::Fr;
    use ark_ff::One;
    use ark_std::test_rng;

    use crate::composer::{Composer, Table};
    use crate::verifier::Verifier;
    use crate::GeneralEvaluationDomain;

    use super::*;
    use std::time::Instant; // timer

    #[test]
    fn prover() -> Result<(), Error> {
        let mut cs = {
            // x^3 + x + pi = 35
            let mut cs = Composer::new(4, true);
            let pi = cs.alloc_input(Fr::from(5));
            let x = cs.alloc(Fr::from(3));
            let y = cs.mul(x, x);
            let z = cs.mul(x, y);
            let u = cs.add(x, z);
            let v = cs.add(pi, u);
            cs.enforce_constant(v, Fr::from(35));

            // cs.enforce_range(v, 16)?;

            // let x1 = cs.alloc(Fr::from(1));
            // let x2 = cs.alloc(Fr::from(2));
            // let x3 = cs.alloc(Fr::from(3));
            // let x4 = cs.alloc(Fr::from(4));
            // let hash = cs.MiMC_sponge(&[x1, x2, x3, x4], 1);
            // println!("hash {}", cs.get_assignment(hash[0]));

            let x4x = cs.alloc(Fr::from(12));
            cs.poly_gate_with_next(
                vec![
                    (x, Fr::one()),
                    (x, Fr::one()),
                    (x, Fr::one()),
                    (x, Fr::one()),
                ],
                Fr::zero(),
                Fr::zero(),
                vec![(x4x, -Fr::one())],
            );
            cs.fully_costomizable_poly_gates(
                vec![
                    vec![
                        (x, Fr::one()),
                        (x, Fr::one()),
                        (x, Fr::one()),
                        (x, Fr::one()),
                    ],
                    vec![
                        (x4x, -Fr::one()),
                        (x, Fr::one()),
                        (x, Fr::one()),
                        (x, Fr::one()),
                    ],
                    vec![(x, Fr::one()), (x, -Fr::one())],
                ],
                vec![Fr::one(), Fr::one(), Fr::one()],
                vec![Fr::zero(), Fr::zero(), Fr::zero()],
                vec![Fr::zero(), Fr::zero(), Fr::zero()],
                vec![-Fr::one(), Fr::one(), Fr::zero()],
            );

            let table_index = cs.add_table(Table::xor_table(4));
            let xtt = cs.alloc(Fr::from(1));
            let ytt = cs.alloc(Fr::from(2));
            let ztt = cs.read_from_table(table_index, vec![xtt, ytt])?;
            cs.enforce_constant(ztt[0], Fr::from(3));

            cs
        };
        let public_input = cs.compute_public_input();
        println!("circuit construct complete");

        let rng = &mut test_rng();

        println!("time start:");
        let start = Instant::now();
        println!("compute_prover_key...");
        let pk = cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()?;
        println!("compute_prover_key...done");

        let pckey = PCKey::<ark_bn254::Bn254>::setup(pk.domain_size() + pk.program_width + 6, rng);

        let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, ark_bn254::Bn254>::new(pk);
        println!("init_comms...");
        let verifier_comms = prover.init_comms(&pckey);
        println!("init_comms...done");
        println!("time cost: {:?} ms", start.elapsed().as_millis()); // ms

        let mut verifier = Verifier::new(&prover, &public_input, &verifier_comms);

        let proof = prover.prove(&mut cs, &pckey, rng)?;

        let sha256_of_srs = pckey.sha256_of_srs();
        verifier.verify(&pckey.vk, &proof, &sha256_of_srs);

        Ok(())
    }
}
