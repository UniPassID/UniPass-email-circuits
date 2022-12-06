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


#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractTripleInput {
    pub first_from_left_index: u32,
    pub first_from_len: u32,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub first_header_pub_match: Vec<u8>,

    pub second_from_left_index: u32,
    pub second_from_len: u32,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub second_header_pub_match: Vec<u8>,

    pub third_from_left_index: u32,
    pub third_from_len: u32,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub third_header_pub_match: Vec<u8>,

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

impl ContractTripleInput {
    pub fn new<F: PrimeField, D: Domain<F>, E: PairingEngine>(
        first_from_left_index: u32,
        first_from_len: u32,
        first_header_pub_match: Vec<u8>,
        second_from_left_index: u32,
        second_from_len: u32,
        second_header_pub_match: Vec<u8>,
        third_from_left_index: u32,
        third_from_len: u32,
        third_header_pub_match: Vec<u8>,
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
            public_inputs_num,
            domain_size,
            vk_data,
            public_inputs,
            proof: proof_data,
            srs_hash: srs_hash.clone(),
            first_from_left_index,
            first_from_len,
            first_header_pub_match,
            second_from_left_index,
            second_from_len,
            second_header_pub_match,
            third_from_left_index,
            third_from_len,
            third_header_pub_match,
        }
    }
}
