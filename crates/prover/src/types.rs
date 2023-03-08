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
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub header_hash: Vec<u8>,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub addr_hash: Vec<u8>,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub header_pub_match: Vec<u8>,
    pub header_len: u32,
    pub from_left_index: u32,
    pub from_len: u32,
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
        header_hash: Vec<u8>,
        addr_hash: Vec<u8>,
        header_pub_match: Vec<u8>,
        header_len: u32,
        from_left_index: u32,
        from_len: u32,
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
            header_hash,
            addr_hash,
            header_pub_match,
            header_len,
            from_left_index,
            from_len,
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
pub struct Bytes(
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    Vec<u8>,
);

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractTripleInput {
    pub header_hashs: Vec<Bytes>,
    pub addr_hashs: Vec<Bytes>,
    pub header_pub_matches: Vec<Bytes>,
    pub header_lens: Vec<u32>,
    pub from_left_indexes: Vec<u32>,
    pub from_lens: Vec<u32>,

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
        header_hashs: Vec<Vec<u8>>,
        addr_hashs: Vec<Vec<u8>>,
        header_pub_matches: Vec<Vec<u8>>,
        header_lens: Vec<u32>,
        from_left_indexes: Vec<u32>,
        from_lens: Vec<u32>,

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
            header_hashs: header_hashs
                .into_iter()
                .map(|header_hash| Bytes(header_hash))
                .collect(),
            addr_hashs: addr_hashs
                .into_iter()
                .map(|addr_hash| Bytes(addr_hash))
                .collect(),
            header_pub_matches: header_pub_matches
                .into_iter()
                .map(|header_pub_match| Bytes(header_pub_match))
                .collect(),
            header_lens,
            from_left_indexes,
            from_lens,
            public_inputs_num,
            domain_size,
            vk_data,
            public_inputs,
            proof: proof_data,
            srs_hash: srs_hash.clone(),
        }
    }
}
