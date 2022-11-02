use std::fs::File;

use ark_ec::PairingEngine;
use ark_ff::BigInteger;
use ark_ff::BigInteger128;
use ark_ff::ToBytes;
use ark_poly_commit::kzg10::Commitment;
use ark_std::Zero;

use crate::proof::Proof;
use crate::Domain;
use crate::Field;

pub fn serialize_for_contract<F: Field, D: Domain<F>, E: PairingEngine>(
    file_name: String,
    pi_num: usize,
    domain: D,
    verifier_comms: &Vec<Commitment<E>>,
    g2x: E::G2Affine,
    proof: &Proof<F, E>,
) {
    {
        let mut buffer = File::create(file_name).unwrap();
        // domain size
        let v0_domainsize = BigInteger128::from(domain.size() as u64);
        let _ = v0_domainsize.to_bytes_be().write(&mut buffer);
        // publicinput number
        let pi_num = BigInteger128::from(pi_num as u64);
        let _ = pi_num.to_bytes_be().write(&mut buffer);
        // omega
        let omega = domain.generator();
        let _ = omega.into_repr().to_bytes_be().write(&mut buffer);

        // vk
        for c in verifier_comms {
            let tmp = c.0;
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
                let _ = x.write(&mut buffer);
                let _ = x.write(&mut buffer);
            } else {
                let _ = x.write(&mut buffer);
                let _ = y.write(&mut buffer);
            }
        }

        // g2x
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

        let _ = xc0.write(&mut buffer);
        let _ = xc1.write(&mut buffer);
        let _ = yc0.write(&mut buffer);
        let _ = yc1.write(&mut buffer);

        // proof
        for c in &proof.commitments1 {
            let tmp = c.0;
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
                let _ = x.write(&mut buffer);
                let _ = x.write(&mut buffer);
            } else {
                let _ = x.write(&mut buffer);
                let _ = y.write(&mut buffer);
            }
        }

        let tmp = proof.commitment2.0;
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
            let _ = x.write(&mut buffer);
            let _ = x.write(&mut buffer);
        } else {
            let _ = x.write(&mut buffer);
            let _ = y.write(&mut buffer);
        }

        for c in &proof.commitments3 {
            let tmp = c.0;
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
                let _ = x.write(&mut buffer);
                let _ = x.write(&mut buffer);
            } else {
                let _ = x.write(&mut buffer);
                let _ = y.write(&mut buffer);
            }
        }
        for c in &proof.commitments4 {
            let tmp = c.0;
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
                let _ = x.write(&mut buffer);
                let _ = x.write(&mut buffer);
            } else {
                let _ = x.write(&mut buffer);
                let _ = y.write(&mut buffer);
            }
        }
        for e in &proof.evaluations {
            let _ = e.into_repr().to_bytes_be().write(&mut buffer);
        }
        for e in &proof.evaluations_alt_point {
            let _ = e.into_repr().to_bytes_be().write(&mut buffer);
        }

        let tmp = proof.Wz_pi.0;
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
            let _ = x.write(&mut buffer);
            let _ = x.write(&mut buffer);
        } else {
            let _ = x.write(&mut buffer);
            let _ = y.write(&mut buffer);
        }

        let tmp = proof.Wzw_pi.0;
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
            let _ = x.write(&mut buffer);
            let _ = x.write(&mut buffer);
        } else {
            let _ = x.write(&mut buffer);
            let _ = y.write(&mut buffer);
        }
    }
}
