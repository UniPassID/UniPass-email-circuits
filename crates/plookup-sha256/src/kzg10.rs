use ark_ec::msm::FixedBaseMSM;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::ToBytes;
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use ark_poly_commit::kzg10::Commitment;
use ark_serialize::*;
use ark_std::cfg_into_iter;
use ark_std::{rand::RngCore, vec, vec::Vec};
use sha2::{Digest, Sha256};
use std::ops::Div;

use crate::utils::convert_to_bigints;
use rayon::prelude::*;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct PCKey<E: PairingEngine> {
    /// The key used to commit to polynomials.
    pub powers: Vec<E::G1Affine>,
    /// The maximum degree supported by the `UniversalParams` `self` was derived from.
    pub max_degree: usize,

    pub vk: VKey<E>,
}

#[derive(Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct VKey<E: PairingEngine> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,

    pub max_degree: usize,
}

impl<E: PairingEngine> PCKey<E> {
    pub fn setup<R>(max_degree: usize, rng: &mut R) -> Self
    where
        R: RngCore,
    {
        println!("[setup] start to setup...");
        let beta = E::Fr::rand(rng);

        let g = E::G1Projective::prime_subgroup_generator();
        let h = E::G2Projective::prime_subgroup_generator();
        println!("[setup] generate...ok.");

        let mut powers_of_beta = vec![E::Fr::one()];

        let mut cur = beta;
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }

        let window_size = FixedBaseMSM::get_mul_window_size(max_degree + 1);

        let scalar_bits = E::Fr::size_in_bits();
        let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
        let powers_of_g = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
            scalar_bits,
            window_size,
            &g_table,
            &powers_of_beta,
        );
        let powers_of_g = E::G1Projective::batch_normalization_into_affine(&powers_of_g);

        println!(
            "[setup] generate powers_of_g1...ok. max_degree = {}",
            max_degree
        );

        let vk = VKey::<E> {
            g: g.into_affine(),
            h: h.into_affine(),
            beta_h: h.into_affine().mul(beta).into_affine(),
            max_degree,
        };
        let pckey = PCKey::<E> {
            powers: powers_of_g,
            max_degree,
            vk: vk.clone(),
        };
        println!("[setup]finish.");
        pckey
    }

    pub fn commit_vec<F: PrimeField>(
        &self,
        polynomials: &[DensePolynomial<F>],
    ) -> Vec<Commitment<E>> {
        let comms = cfg_into_iter!(polynomials)
            .map(|p| self.commit_one(p))
            .collect();

        comms
    }

    pub fn commit_one<F: PrimeField>(&self, polynomial: &DensePolynomial<F>) -> Commitment<E> {
        let num_coefficient = polynomial.coeffs.len();

        assert!(num_coefficient <= self.max_degree + 1);

        let coef = &polynomial.coeffs;
        let coe: Vec<_> = coef
            .par_iter()
            .map(|v| E::Fr::from(v.into_repr().into()))
            .collect();

        let coeffs_bignum = convert_to_bigints(&coe);

        let commitment = VariableBaseMSM::multi_scalar_mul(&self.powers, &coeffs_bignum);

        let c = Commitment::<E> {
            0: commitment.into_affine(),
        };
        c
    }

    pub fn open_one<F: PrimeField>(
        &self,
        polynomial: &DensePolynomial<F>,
        point: F,
    ) -> Commitment<E> {
        let point = E::Fr::from(point.into_repr().into());

        let num_coefficient = polynomial.coeffs.len();
        assert!(num_coefficient <= self.max_degree + 1);

        let coef = &polynomial.coeffs;
        let coe = coef
            .par_iter()
            .map(|v| E::Fr::from(v.into_repr().into()))
            .collect();

        let polynomial = DensePolynomial::from_coefficients_vec(coe);

        let divisor = DensePolynomial::from_coefficients_vec(vec![-point, E::Fr::one()]);
        //no need sub value
        let witness_polynomial = polynomial.div(&divisor);

        let coeffs_bignum = convert_to_bigints(&witness_polynomial.coeffs);

        let commitment = VariableBaseMSM::multi_scalar_mul(&self.powers, &coeffs_bignum);

        let c = Commitment::<E> {
            0: commitment.into_affine(),
        };

        c
    }

    pub fn compute_batched_proof_pi<'a>(
        &self,
        comms: &[Commitment<E>],
        eta: E::Fr,
    ) -> Commitment<E> {
        let len = comms.len();

        let mut pi_res = E::G1Projective::zero();
        let mut eta_pow = E::Fr::one();

        for i in 0..len {
            let tmp = comms[i].0.into_projective().mul(eta_pow.into_repr());
            pi_res += tmp;

            eta_pow *= eta;
        }

        Commitment::<E> {
            0: pi_res.into_affine(),
        }
    }

    pub fn max_degree(&self) -> usize {
        self.max_degree
    }

    pub fn sha256_of_srs(&self) -> Vec<u8> {
        let mut srshasher = Sha256::new();
        for srs in &self.powers {
            let mut bytes = [0u8; 64];
            let _ = srs.write(bytes.as_mut());
            let mut x = [0u8; 32];
            for j in 0..32 {
                x[32 - j - 1] = bytes[j];
            }
            let mut y = [0u8; 32];
            for j in 32..64 {
                y[64 - j - 1] = bytes[j];
            }
            
            srshasher.update(x);
            srshasher.update(y);
        }
        
        srshasher.finalize().to_vec()
    }
}

impl<E: PairingEngine> VKey<E> {
    pub fn verify_pc<F: PrimeField>(
        &self,
        comm: &Commitment<E>,
        point: F,
        point_eval: F,
        pi: &Commitment<E>,
    ) -> bool {
        let point = E::Fr::from(point.into_repr().into());
        let point_eval = E::Fr::from(point_eval.into_repr().into());

        // e(comm − eval * G0, H0) = e(π, H1 − ζH0).
        let inner = comm.0.into_projective() - self.g.into_projective().mul(point_eval.into_repr());

        // e(ζ * π + comm − eval * G0, H0) = e(π, H1).
        let left = pi.0.into_projective().mul(point.into_repr()) + inner;
        let lhs = E::pairing(left, self.h);
        let rhs = E::pairing(pi.0, self.beta_h);
        if lhs != rhs {
            return false;
        }

        true
    }

    pub fn verify_batched_pc<F: PrimeField>(
        &self,
        comms: &[Commitment<E>],
        point: F,
        point_evals: &[F],
        pi: &Commitment<E>,
        v: F,
    ) -> bool {
        let point = E::Fr::from(point.into_repr().into());
        let v = E::Fr::from(v.into_repr().into());
        let mut point_es = vec![];
        for pe in point_evals {
            point_es.push(E::Fr::from(pe.into_repr().into()))
        }

        let mut batch_comm = E::G1Projective::zero();
        let mut batch_eval = E::Fr::zero();
        let mut v_pow = E::Fr::one();

        let batch_num = comms.len();
        assert_eq!(batch_num, point_evals.len());
        for i in 0..batch_num {
            batch_comm = batch_comm + comms[i].0.into_projective().mul(v_pow.into_repr());

            batch_eval = batch_eval + point_es[i] * v_pow;

            v_pow = v * v_pow;
        }

        // e(ζ * π + comm − eval * G0, H0) = e(π, H1).
        let inner = batch_comm - self.g.into_projective().mul(batch_eval.into_repr());
        let left = pi.0.into_projective().mul(point.into_repr()) + inner;

        let lhs = E::pairing(left, self.h);
        let rhs = E::pairing(pi.0, self.beta_h);

        if lhs != rhs {
            return false;
        }

        true
    }

    pub fn batch_verify_multi_point_open_pc<F: PrimeField>(
        &self,
        comms: &[Commitment<E>],
        points: &[F],
        point_evals: &[F],
        pis: &[Commitment<E>],
        v: F,
    ) -> bool {
        let points = {
            let mut pt = vec![];
            for p in points {
                pt.push(E::Fr::from(p.into_repr().into()));
            }
            pt
        };
        let v = E::Fr::from(v.into_repr().into());
        let point_evals = {
            let mut pes = vec![];
            for pe in point_evals {
                pes.push(E::Fr::from(pe.into_repr().into()))
            }
            pes
        };

        // e( Σ[u^i * (ζi * πi + commi − evali * G0)], H0) = e(Σ[u^i * πi], H1).
        // e( Σ[(u^i * ζi) * πi + u^i * commi)] - Σ[u^i * evali]*G0)], H0) = e(Σ[u^i * πi], H1).
        let mut v_pow = E::Fr::one();
        let mut batch_eval = E::Fr::zero();
        let mut right = E::G1Projective::zero();
        let mut left = E::G1Projective::zero();

        let batch_num = comms.len();
        assert_eq!(batch_num, point_evals.len());
        assert_eq!(batch_num, points.len());
        assert_eq!(batch_num, pis.len());
        for i in 0..batch_num {
            let uipi = v_pow * points[i];

            batch_eval += point_evals[i] * v_pow;

            left += pis[i].0.into_projective().mul(uipi.into_repr());
            left += comms[i].0.into_projective().mul(v_pow.into_repr());

            right += pis[i].0.into_projective().mul(v_pow.into_repr());

            v_pow = v * v_pow;
        }

        left -= self.g.into_projective().mul(batch_eval.into_repr());

        let lhs = E::pairing(left, self.h);
        let rhs = E::pairing(right, self.beta_h);

        if lhs != rhs {
            return false;
        }

        true
    }

    pub fn max_degree(&self) -> usize {
        self.max_degree
    }
}
