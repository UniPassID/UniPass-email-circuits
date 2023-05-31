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
        log::trace!("[setup] start to setup...");
        let beta = E::Fr::rand(rng);

        let g = E::G1Projective::prime_subgroup_generator();
        let h = E::G2Projective::prime_subgroup_generator();
        log::trace!("[setup] generate...ok.");

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

        log::trace!(
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
            vk,
        };
        log::trace!("[setup]finish.");
        pckey
    }

    pub fn check(&self) -> bool {
        !(!E::pairing(self.powers[0], self.vk.beta_h).eq(&E::pairing(self.powers[1], self.vk.h)))
    }

    pub fn apply_new_rand(&self, new_beta: E::Fr) -> Self {
        let mut powers_of_new_beta = vec![E::Fr::one()];
        let mut cur = new_beta;
        for _ in 0..self.max_degree {
            powers_of_new_beta.push(cur);
            cur *= &new_beta;
        }
        let powers = self.powers.clone();
        let new_powers_of_g: Vec<_> = powers
            .into_par_iter()
            .zip(powers_of_new_beta)
            .map(|(power_of_g, beta)| power_of_g.mul(beta))
            .collect();
        let new_powers_of_g = E::G1Projective::batch_normalization_into_affine(&new_powers_of_g);
        let new_beta_h = self.vk.beta_h.mul(new_beta).into_affine();
        let vk = VKey::<E> {
            g: self.vk.g,
            h: self.vk.h,
            beta_h: new_beta_h,
            max_degree: self.max_degree,
        };

        
        PCKey::<E> {
            powers: new_powers_of_g,
            max_degree: self.max_degree,
            vk,
        }
    }

    pub fn commit_vec<F: PrimeField>(
        &self,
        polynomials: &[DensePolynomial<F>],
    ) -> Vec<Commitment<E>> {
        

        cfg_into_iter!(polynomials)
            .map(|p| self.commit_one(p))
            .collect()
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

        
        Commitment::<E>(commitment.into_affine())
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

        

        Commitment::<E>(commitment.into_affine())
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

        Commitment::<E>(pi_res.into_affine())
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
            batch_comm += comms[i].0.into_projective().mul(v_pow.into_repr());

            batch_eval += point_es[i] * v_pow;

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

#[cfg(test)]
mod tests {
    use ark_poly::Polynomial;
    // use rand_core::OsRng;
    // use ark_std::rand::thread_rng;
    use ark_bn254::Fr;
    use ark_std::test_rng;

    use crate::Error;

    use super::*;

    #[test]
    fn test_setup() -> Result<(), Error> {
        // let rng = &mut thread_rng();
        let rng = &mut test_rng();
        let pckey = PCKey::<ark_bn254::Bn254>::setup(16, rng);

        pckey.check();

        Ok(())
    }

    #[test]
    fn test_structure_check() -> Result<(), Error> {
        // let rng = &mut thread_rng();
        let n = 16;
        let rng = &mut test_rng();
        let pckey = PCKey::<ark_bn254::Bn254>::setup(n, rng);

        let x = Fr::rand(&mut test_rng());
        let mut challenges = vec![];
        challenges.push(x);
        for i in 0..n - 1 {
            challenges.push(challenges[i] * x);
        }

        let left = pckey.powers[0..(n - 1)].to_vec();
        let right = pckey.powers[1..n].to_vec();
        let scalars: Vec<_> = challenges.iter().map(|scalar| scalar.into_repr()).collect();

        let L_comm = VariableBaseMSM::multi_scalar_mul(&left, &scalars);
        let R_comm = VariableBaseMSM::multi_scalar_mul(&right, &scalars);
        let p1 = ark_bn254::Bn254::pairing(L_comm, pckey.vk.beta_h);
        let p2 = ark_bn254::Bn254::pairing(R_comm, pckey.vk.h);

        assert_eq!(p1, p2);

        Ok(())
    }

    #[test]
    fn test_verify() -> Result<(), Error> {
        let n = 16;
        let rng = &mut test_rng();
        let pckey = PCKey::<ark_bn254::Bn254>::setup(n, rng);

        let test_poly = DensePolynomial::from_coefficients_vec(vec![Fr::one(); n]);

        let c = pckey.commit_one(&test_poly);

        let point = Fr::rand(&mut test_rng());
        let point_eval = test_poly.evaluate(&point);
        let pi = pckey.open_one(&test_poly, point);

        let res = pckey.vk.verify_pc(&c, point, point_eval, &pi);
        assert!(res);
        Ok(())
    }

    #[test]
    fn test_batch_verify() -> Result<(), Error> {
        let n = 16;
        let rng = &mut test_rng();
        let pckey = PCKey::<ark_bn254::Bn254>::setup(n, rng);

        let x = Fr::rand(&mut test_rng());
        let num = 3;
        let mut polys = vec![];
        for _ in 0..num {
            let mut coeffs = vec![];
            for _ in 0..n {
                coeffs.push(Fr::rand(&mut test_rng()));
            }
            let test_poly = DensePolynomial::from_coefficients_vec(coeffs);
            polys.push(test_poly);
        }

        let c = pckey.commit_vec(&polys);

        let point = Fr::rand(&mut test_rng());
        let point_evals: Vec<_> = polys.iter().map(|p| p.evaluate(&point)).collect();
        let pis: Vec<_> = polys.iter().map(|p| pckey.open_one(p, point)).collect();
        let batched_pi = pckey.compute_batched_proof_pi(&pis, x);

        let res = pckey
            .vk
            .verify_batched_pc(&c, point, &point_evals, &batched_pi, x);
        assert!(res);
        Ok(())
    }

    #[test]
    fn test_multi_point_verify() -> Result<(), Error> {
        let n = 16;
        let rng = &mut test_rng();
        let pckey = PCKey::<ark_bn254::Bn254>::setup(n, rng);

        let x = Fr::rand(&mut test_rng());
        let num = 3;
        let mut polys = vec![];
        for _ in 0..num {
            let mut coeffs = vec![];
            for _ in 0..n {
                coeffs.push(Fr::rand(&mut test_rng()));
            }
            let test_poly = DensePolynomial::from_coefficients_vec(coeffs);
            polys.push(test_poly);
        }

        let c = pckey.commit_vec(&polys);

        let points: Vec<_> = (0..num).map(|_i| Fr::rand(&mut test_rng())).collect();
        let point_evals: Vec<_> = polys
            .iter()
            .zip(&points)
            .map(|(p, point)| p.evaluate(point))
            .collect();
        let pis: Vec<_> = polys
            .iter()
            .zip(&points)
            .map(|(p, point)| pckey.open_one(p, *point))
            .collect();

        let res = pckey
            .vk
            .batch_verify_multi_point_open_pc(&c, &points, &point_evals, &pis, x);
        assert!(res);
        Ok(())
    }
}
