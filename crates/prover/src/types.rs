use email_parser::types::{deserialize_hex_string, serialize_hex_string};
use plonk::ark_ec::PairingEngine;
use plonk::ark_ff::{BigInteger, BigInteger128, PrimeField};
use plonk::ark_poly_commit::kzg10::Commitment;
use plonk::{proof::Proof, Domain};
use serde::{Deserialize, Serialize};

use crate::utils::{convert_proof, convert_public_inputs, convert_vk_data};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractInput {
    pub from_left_index: u32,
    pub from_len: u32,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub header_pub_match: Vec<u8>,
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
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub srs_hash: Vec<u8>,
}

impl ContractInput {
    pub fn new<F: PrimeField, D: Domain<F>, E: PairingEngine>(
        from_left_index: u32,
        from_len: u32,
        header_pub_match: Vec<u8>,
        public_inputs: &[F],
        domain: D,
        verifier_comms: &Vec<Commitment<E>>,
        g2x: E::G2Affine,
        proof: &Proof<F, E>,
        srs_hash: &Vec<u8>,
    ) -> Self {
        // domain size
        let v0_domainsize = BigInteger128::from(domain.size() as u64);
        let domain_size = v0_domainsize.to_bytes_be();

        // publicinput number
        let public_inputs_num = BigInteger128::from(public_inputs.len() as u64);
        let public_inputs_num = public_inputs_num.to_bytes_be();

        let vk_data = convert_vk_data(domain, verifier_comms, g2x);
        let proof_data = convert_proof(proof);
        let public_inputs = convert_public_inputs(public_inputs);
        Self {
            from_left_index,
            from_len,
            header_pub_match,
            public_inputs_num,
            domain_size,
            vk_data,
            public_inputs,
            proof: proof_data,
            srs_hash: srs_hash.clone(),
        }
    }
}
