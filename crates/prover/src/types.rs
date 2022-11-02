use ark_ec::PairingEngine;
use ark_ff::{BigInteger, BigInteger128, PrimeField, ToBytes};
use ark_poly_commit::kzg10::Commitment;
use ark_std::Zero;
use plonk::{proof::Proof, Domain};
use serde::{Deserialize, Serialize};

use crate::utils::{
    convert_public_inputs, deserialize_hex_string, serialize_hex_string, to_0x_hex,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractInput {
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub public_inputs_num: Vec<u8>,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub domain_size: Vec<u8>,
    pub vk_data: Vec<String>,
    pub public_inputs: Vec<String>,
    pub proof: Vec<String>,
}

impl ContractInput {
    pub fn new<F: PrimeField, D: Domain<F>, E: PairingEngine>(
        public_inputs: &[F],
        domain: D,
        verifier_comms: &Vec<Commitment<E>>,
        g2x: E::G2Affine,
        proof: &Proof<F, E>,
    ) -> Self {
        // domain size
        let v0_domainsize = BigInteger128::from(domain.size() as u64);
        let domain_size = v0_domainsize.to_bytes_be();

        // publicinput number
        let public_inputs_num = BigInteger128::from(public_inputs.len() as u64);
        let public_inputs_num = public_inputs_num.to_bytes_be();

        let mut vk_data = vec![];
        // omega
        let omega = domain.generator();
        let mut x = [0u8; 32];
        let _ = omega.into_repr().to_bytes_be().write(&mut x[..]);
        vk_data.push(to_0x_hex(x));

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
                vk_data.push(to_0x_hex(x));
                vk_data.push(to_0x_hex(x));
            } else {
                vk_data.push(to_0x_hex(x));
                vk_data.push(to_0x_hex(y));
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

        vk_data.push(to_0x_hex(xc0));
        vk_data.push(to_0x_hex(xc1));
        vk_data.push(to_0x_hex(yc0));
        vk_data.push(to_0x_hex(yc1));

        let mut proof_data = vec![];

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
                proof_data.push(to_0x_hex(x));
                proof_data.push(to_0x_hex(x));
            } else {
                proof_data.push(to_0x_hex(x));
                proof_data.push(to_0x_hex(y));
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
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(x));
        } else {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(y));
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
                proof_data.push(to_0x_hex(x));
                proof_data.push(to_0x_hex(x));
            } else {
                proof_data.push(to_0x_hex(x));
                proof_data.push(to_0x_hex(y));
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
                proof_data.push(to_0x_hex(x));
                proof_data.push(to_0x_hex(x));
            } else {
                proof_data.push(to_0x_hex(x));
                proof_data.push(to_0x_hex(y));
            }
        }
        let mut buf = [0u8; 32];
        for e in &proof.evaluations {
            let _ = e.into_repr().to_bytes_be().write(&mut buf[..]);
            proof_data.push(to_0x_hex(buf));
        }
        for e in &proof.evaluations_alt_point {
            let _ = e.into_repr().to_bytes_be().write(&mut buf[..]);
            proof_data.push(to_0x_hex(buf));
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
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(x));
        } else {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(y));
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
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(x));
        } else {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(y));
        }

        let public_inputs = convert_public_inputs(public_inputs);
        Self {
            public_inputs_num,
            domain_size,
            vk_data,
            public_inputs,
            proof: proof_data,
        }
    }
}
