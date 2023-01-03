use std::time::Instant;

use crate::{
    coset_generator, gen_verify_comms_labels, gen_verify_open_zeta_labels,
    gen_verify_open_zeta_omega_labels,
};
use crate::{
    kzg10::VKey, proof::Proof, prover::Prover, transcript::TranscriptLibrary, Domain, Field, Map,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, ToBytes, Zero};
use ark_poly::{Evaluations, Polynomial};
use ark_poly_commit::kzg10::Commitment;
use sha2::{Digest, Sha256};

#[cfg(feature = "parallel")]
// use rayon::prelude::*;

fn quad<F: Field>(lower: F, higher: F) -> F {
    let mut v = lower;
    v += v;
    v += v;
    v = higher - v;
    (0..4).into_iter().map(|i| v - F::from(i as u64)).product()
}

/// out = values[0] + challenge *values[1] +...+ challenge^n *values[n-1]
fn combine<F: Field>(challenge: F, mut values: Vec<F>) -> F {
    let mut acc = F::zero();
    while let Some(v) = values.pop() {
        acc = acc * challenge + v
    }

    acc
}

pub struct Verifier<F: Field, D: Domain<F>, E: PairingEngine> {
    pub program_width: usize,
    pub enable_range: bool,
    pub enable_lookup: bool,
    pub enable_mimc: bool,
    pub enable_mask_poly: bool,
    pub enable_pubmatch: bool,

    pub public_input: Vec<F>,
    pub commitments: Map<String, Commitment<E>>,
    pub evaluations: Map<String, F>,

    pub domain_generator: F,

    pub domain: D,
}

impl<F: Field, D: Domain<F>, E: PairingEngine> Verifier<F, D, E> {
    pub fn new(
        prover: &Prover<F, D, E>,
        public_input: &Vec<F>,
        v_comms: &Vec<Commitment<E>>,
    ) -> Self {
        let mut commitments = Map::new();
        let labels = gen_verify_comms_labels(
            prover.program_width,
            prover.enable_range,
            prover.enable_lookup,
            prover.enable_mimc,
            prover.enable_mask_poly,
            prover.enable_pubmatch,
        );
        for (str, comm) in labels.iter().zip(v_comms) {
            commitments.insert(str.to_string(), comm.clone());
        }

        Self {
            program_width: prover.program_width,
            commitments,
            domain: prover.domain,
            domain_generator: prover.domain.generator(),
            enable_range: prover.enable_range,
            enable_lookup: prover.enable_lookup,
            enable_mimc: prover.enable_mimc,
            enable_mask_poly: prover.enable_mask_poly,
            evaluations: Map::new(),
            enable_pubmatch: prover.enable_pubmatch,
            public_input: public_input.clone(),
        }
    }

    pub fn verify(&mut self, pcvk: &VKey<E>, proof: &Proof<F, E>, sha256_of_srs: &Vec<u8>) -> bool {
        log::trace!("verify time start:");
        let start = Instant::now();

        let mut z_labels = vec!["z".to_string(), "z_lookup".to_string()];
        if self.enable_mask_poly {
            z_labels.push("z_substring".to_string());
        }
        let verify_open_zeta_labels =
            gen_verify_open_zeta_labels(self.program_width, self.enable_lookup);
        let verify_open_zeta_omega_labels =
            gen_verify_open_zeta_omega_labels(self.enable_lookup, self.enable_mask_poly);

        let mut trans = TranscriptLibrary::new();
        // sha256 SRS, put into the transcript
        trans.update_with_u256(sha256_of_srs);

        let pi_num = self.public_input.len() as u64;
        let v0_domainsize = self.domain.size() as u128;
        let omega = self.domain.generator();
        let mut vcomms = vec![];
        let mut g2xbytes = vec![];

        let verify_comms_labels = gen_verify_comms_labels(
            self.program_width,
            self.enable_range,
            self.enable_lookup,
            self.enable_mimc,
            self.enable_mask_poly,
            self.enable_pubmatch,
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
        let g2x = pcvk.beta_h;
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

        for pi in &self.public_input {
            trans.update_with_fr(pi);
        }

        // step 1
        for (i, ci) in proof.commitments1.iter().enumerate() {
            trans.update_with_g1::<E>(&ci.0);
            self.commitments.insert(format!("w_{}", i), ci.clone());
        }
        let eta = trans.generate_challenge::<F>();

        // step 2
        trans.update_with_g1::<E>(&proof.commitment2.0);
        self.commitments
            .insert(format!("s"), proof.commitment2.clone());
        let beta = trans.generate_challenge::<F>();
        let gamma = trans.generate_challenge::<F>();

        // step 3
        for (ci, str) in proof.commitments3.iter().zip(z_labels) {
            trans.update_with_g1::<E>(&ci.0);
            self.commitments.insert(str, ci.clone());
        }
        let alpha = trans.generate_challenge::<F>();

        // step 4
        for (i, ci) in proof.commitments4.iter().enumerate() {
            trans.update_with_g1::<E>(&ci.0);
            self.commitments.insert(format!("t_{}", i), ci.clone());
        }
        let zeta = trans.generate_challenge::<F>();

        for (ei, str) in proof.evaluations.iter().zip(&verify_open_zeta_labels) {
            trans.update_with_fr(ei);
            self.evaluations.insert(format!("{}_zeta", str), *ei);
        }
        for (ei, str) in proof
            .evaluations_alt_point
            .iter()
            .zip(&verify_open_zeta_omega_labels)
        {
            trans.update_with_fr(ei);
            self.evaluations.insert(format!("{}_zeta_omega", str), *ei);
        }
        let v = trans.generate_challenge::<F>();

        trans.update_with_g1::<E>(&proof.Wz_pi.0);
        trans.update_with_g1::<E>(&proof.Wzw_pi.0);
        let u = trans.generate_challenge::<F>();

        let lagrange_1_zeta = self.domain.evaluate_lagrange_polynomial(1, &zeta);
        let lagrange_n_zeta = self
            .domain
            .evaluate_lagrange_polynomial(self.domain.size(), &zeta);
        let alpha_2 = alpha.square();
        let alpha_3 = alpha * alpha_2;
        let alpha_4 = alpha_2.square();
        let alpha_5 = alpha * alpha_4;

        // cal r_complement
        let mut tmp = F::one();
        for i in 0..self.program_width - 1 {
            tmp *= self.evaluations[&format!("w_{}_zeta", i)]
                + beta * self.evaluations[&format!("sigma_{}_zeta", i)]
                + gamma
        }
        let mut alpha_combinator = alpha;
        let r_permu = alpha_combinator
            * (tmp
                * (self.evaluations[&format!("w_{}_zeta", self.program_width - 1)] + gamma)
                * self.evaluations["z_zeta_omega"]
                + alpha * lagrange_1_zeta);
        // permu
        alpha_combinator *= alpha_2;
        // lookup
        let r_lookup = alpha_combinator
            * (self.evaluations["z_lookup_zeta_omega"]
                * gamma
                * (beta * self.evaluations["s_zeta_omega"] + (beta + F::one()) * gamma)
                + alpha * lagrange_1_zeta
                + alpha_2 * lagrange_n_zeta);
        alpha_combinator *= alpha_3;
        let mut r_complement = r_permu + r_lookup;
        // range
        if self.enable_range {
            alpha_combinator *= alpha;
        }
        // substring
        if self.enable_mask_poly {
            r_complement += alpha_combinator * (-self.evaluations["z_substring_zeta_omega"]);

            alpha_combinator *= alpha_5 * alpha;
        }
        // pubmatch
        if self.enable_pubmatch {
            alpha_combinator *= alpha;
        }
        // mimc
        if self.enable_mimc {
            alpha_combinator *= alpha;
        }

        let pi_poly =
            Evaluations::from_vec_and_domain(self.public_input.clone(), self.domain).interpolate();
        log::trace!("check equality...");
        let lhs = {
            let v_zeta = self.domain.evaluate_vanishing_polynomial(zeta);
            self.evaluations["t4t_zeta"] * v_zeta
        };
        let rhs = {
            let pi_zeta = pi_poly.evaluate(&zeta);

            self.evaluations["r_zeta"] - r_complement - self.evaluations["q_arith_zeta"] * pi_zeta
        };

        if lhs != rhs {
            log::info!("equality check fail");
            return false;
        }
        log::trace!("check equality done");

        log::trace!("pc check...");
        let zeta_n = zeta.pow(&[self.domain.size() as u64]);

        //linear combine commitments at zeta. fixed order
        let cal_combine_comm_zeta = {
            let mut cal_Wz_comm = E::G1Projective::zero();
            let mut comb = F::one();

            //cal t4t comm
            cal_Wz_comm += self.commitments["t_0"].0.into_projective();
            let mut tmp = zeta_n;
            for i in 1..self.program_width {
                cal_Wz_comm += self.commitments[&format!("t_{}", i)]
                    .0
                    .into_projective()
                    .mul(tmp.into_repr());
                tmp *= zeta_n;
            }

            comb = comb * v;

            //cal r comm
            let cal_r_comm = {
                let mut acc = E::G1Projective::zero();
                let mut alpha_combinator = alpha;

                acc += self.commitments["q_m"].0.into_projective().mul(
                    (self.evaluations["q_arith_zeta"]
                        * self.evaluations["w_0_zeta"]
                        * self.evaluations["w_1_zeta"])
                        .into_repr(),
                );
                acc += self.commitments["q_c"]
                    .0
                    .into_projective()
                    .mul((self.evaluations["q_arith_zeta"]).into_repr());
                acc += self.commitments["q0next"].0.into_projective().mul(
                    (self.evaluations["q_arith_zeta"] * self.evaluations["w_0_zeta_omega"])
                        .into_repr(),
                );
                for i in 0..self.program_width {
                    acc += self.commitments[&format!("q_{}", i)]
                        .0
                        .into_projective()
                        .mul(
                            (self.evaluations["q_arith_zeta"]
                                * self.evaluations[&format!("w_{}_zeta", i)])
                                .into_repr(),
                        );
                }

                // z
                let mut tmp = self.evaluations["w_0_zeta"] + beta * zeta + gamma;
                for i in 1..self.program_width {
                    tmp *= self.evaluations[&format!("w_{}_zeta", i)]
                        + beta * zeta * coset_generator::<F>(i)
                        + gamma;
                }
                acc += self.commitments["z"]
                    .0
                    .into_projective()
                    .mul((alpha * (tmp + alpha * lagrange_1_zeta)).into_repr());
                // last sigma!
                let mut tmp = beta * self.evaluations["z_zeta_omega"];
                for i in 0..self.program_width - 1 {
                    tmp *= self.evaluations[&format!("w_{}_zeta", i)]
                        + beta * self.evaluations[&format!("sigma_{}_zeta", i)]
                        + gamma;
                }
                acc += self.commitments[&format!("sigma_{}", self.program_width - 1)]
                    .0
                    .into_projective()
                    .mul((-alpha * (tmp)).into_repr());
                // update alpha_comb
                alpha_combinator *= alpha_2;

                // z_lookup
                let mut twi_zeta = vec![];
                for i in 0..self.program_width {
                    twi_zeta.push(self.evaluations[&format!("w_{}_zeta", i)]);
                }
                twi_zeta.push(self.evaluations["q_table_zeta"]);
                let tmp = combine(eta, twi_zeta);
                acc += self.commitments["z_lookup"].0.into_projective().mul(
                    (alpha_combinator
                        * ((self.evaluations["q_lookup_zeta"] * (tmp) + gamma)
                            * ((self.evaluations["table_zeta"])
                                + beta * (self.evaluations["table_zeta_omega"])
                                + (beta + F::one()) * gamma)
                            + alpha * lagrange_1_zeta
                            + alpha_2 * lagrange_n_zeta))
                        .into_repr(),
                );
                // s
                acc += self.commitments["s"].0.into_projective().mul(
                    (-alpha_combinator * (self.evaluations["z_lookup_zeta_omega"] * gamma))
                        .into_repr(),
                );
                // update alpha_comb
                alpha_combinator *= alpha_3;

                // q_range
                if self.enable_range {
                    let quads = {
                        let mut quads: Vec<_> = (0..self.program_width - 1)
                            .into_iter()
                            .map(|j| {
                                quad(
                                    self.evaluations[&format!("w_{}_zeta", j)],
                                    self.evaluations[&format!("w_{}_zeta", j + 1)],
                                )
                            })
                            .collect();
                        quads.push(quad(
                            self.evaluations[&format!("w_{}_zeta", self.program_width - 1)],
                            self.evaluations["w_0_zeta_omega"],
                        ));

                        quads
                    };

                    acc += self.commitments["q_range"]
                        .0
                        .into_projective()
                        .mul((alpha_combinator * (combine(eta, quads.clone()))).into_repr());

                    alpha_combinator *= alpha;
                }

                // substring:
                if self.enable_mask_poly {
                    // q_substring
                    acc += self.commitments["q_substring"].0.into_projective().mul(
                        (alpha_combinator
                            * (self.evaluations["w_2_zeta"] * self.evaluations["w_3_zeta"]
                                - self.evaluations["w_0_zeta"] * self.evaluations["w_1_zeta"]))
                            .into_repr(),
                    );

                    // q_substring_r
                    acc += self.commitments["q_substring_r"].0.into_projective().mul(
                        (alpha_combinator
                            * (alpha
                                * (self.evaluations["w_1_zeta_omega"]
                                    * self.evaluations["w_4_zeta"]
                                        * (self.evaluations["w_0_zeta"]
                                        + self.evaluations["w_1_zeta_omega"]
                                        - self.evaluations["w_1_zeta"])
                                    - self.evaluations["w_0_zeta_omega"])
                                + alpha_2
                                    * (self.evaluations["w_3_zeta_omega"]
                                        * self.evaluations["w_4_zeta"]
                                            * (self.evaluations["w_2_zeta"]
                                            + self.evaluations["w_3_zeta_omega"]
                                            - self.evaluations["w_3_zeta"])
                                        - self.evaluations["w_2_zeta_omega"])
                                + alpha_4
                                    * (self.evaluations["w_1_zeta_omega"]
                                        * (self.evaluations["w_1_zeta_omega"] - F::one()))
                                + alpha_5
                                    * (self.evaluations["w_3_zeta_omega"]
                                        * (self.evaluations["w_3_zeta_omega"] - F::one()))))
                        .into_repr(),
                    );

                    // z_substring
                    acc += self.commitments["z_substring"].0.into_projective().mul(
                        (alpha_combinator * (alpha_3 * lagrange_1_zeta - F::one())).into_repr(),
                    );

                    // update alpha_comb
                    alpha_combinator *= alpha_5 * alpha;
                }

                // pub match
                if self.enable_pubmatch {
                    // q_q_pubmatch
                    acc += self.commitments["q_pubmatch"].0.into_projective().mul(
                        (alpha_combinator
                            * (self.evaluations["w_1_zeta"]
                                * (self.evaluations["w_0_zeta"] - self.evaluations["w_1_zeta"])))
                            .into_repr(),
                    );

                    // update alpha_comb
                    alpha_combinator *= alpha;
                }

                // q_mimc
                if self.enable_mimc {
                    let tmp1 = self.evaluations["w_0_zeta"] + self.evaluations["w_2_zeta"];
                    let part1 = self.evaluations["w_3_zeta"] - tmp1.square();

                    acc += self.commitments["q_mimc"].0.into_projective().mul(
                        (alpha_combinator
                            * (self.evaluations["w_0_zeta_omega"]
                                - self.evaluations["w_3_zeta"].square() * tmp1
                                - self.evaluations["w_1_zeta"]
                                + eta * part1))
                            .into_repr(),
                    );

                    // update alpha_comb
                    alpha_combinator *= alpha;
                }

                acc
            };

            cal_Wz_comm += cal_r_comm.mul(comb.into_repr());
            comb = comb * v;

            //cal table comm
            let mut cal_table_comm = self.commitments["table_0"].0.into_projective();
            let mut tmp = eta;
            for i in 1..self.program_width + 1 {
                cal_table_comm += self.commitments[&format!("table_{}", i)]
                    .0
                    .into_projective()
                    .mul(tmp.into_repr());
                tmp *= eta;
            }
            let cal_table_comm = Commitment::<E> {
                0: cal_table_comm.into_affine(),
            };
            self.commitments.insert("table".to_string(), cal_table_comm);

            for str in verify_open_zeta_labels.iter().skip(2) {
                let tmp = self.commitments[str.as_str()];
                cal_Wz_comm += tmp.0.into_projective().mul(comb.into_repr());
                comb = comb * v;
            }

            let c = Commitment::<E> {
                0: cal_Wz_comm.into_affine(),
            };
            c
        };
        //combined evaluations at zeta. fixed order
        let mut Wz_poly_eval = F::zero();
        let mut comb = F::one();
        for val in &proof.evaluations {
            Wz_poly_eval += comb * val;
            comb = comb * v;
        }

        //linear combine commitments at omega_zeta. fixed order
        let cal_combine_comm_omega_zeta = {
            let mut cal_wx_comm = E::G1Projective::zero();
            let mut comb = F::one();

            for str in &verify_open_zeta_omega_labels {
                let tmp = self.commitments[str.as_str()];
                cal_wx_comm += tmp.0.into_projective().mul(comb.into_repr());
                comb = comb * v;
            }

            let c = Commitment::<E> {
                0: cal_wx_comm.into_affine(),
            };
            c
        };
        //combined evaluations at omega_zeta. fixed order
        let mut Wzw_poly_eval = F::zero();
        let mut comb = F::one();
        for val in &proof.evaluations_alt_point {
            Wzw_poly_eval += comb * val;
            comb = comb * v;
        }

        // batch multi_point pc check
        let result = {
            let multi_point_pcres = pcvk.batch_verify_multi_point_open_pc(
                &[cal_combine_comm_zeta, cal_combine_comm_omega_zeta],
                &[zeta, zeta * self.domain.generator()],
                &[Wz_poly_eval, Wzw_poly_eval],
                &[proof.Wz_pi, proof.Wzw_pi],
                u,
            );
            log::trace!("multi_point PC? {}", multi_point_pcres);
            multi_point_pcres
        };

        log::trace!("verify time cost: {:?} ms", start.elapsed().as_millis()); // ms
        log::trace!("verify done");

        result
    }
}
