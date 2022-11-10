use std::{fs::File, io};

use plonk::ark_bn254::Bn254;
use plonk::ark_ec::PairingEngine;
use plonk::ark_ff::PrimeField;
use plonk::ark_poly_commit::kzg10::Commitment;
use plonk::ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Write};
use plonk::ark_std::rand::Rng;
use plonk::{
    kzg10::PCKey,
    prover::{Prover, ProverKey},
    Composer, Domain,
};

use crate::ProverResult;

use self::iden3::BinFile;

pub mod iden3;

pub fn read_ptau_to_pckey(p: &str) -> std::io::Result<PCKey<Bn254>> {
    let mut file = File::open(p).unwrap();
    let mut binfile = BinFile::new(&mut file).unwrap();
    log::trace!("binfile: {}", serde_json::to_string(&binfile)?);
    binfile.pckey()
}

pub fn prepare_generic_params<E: PairingEngine>(max_degree: usize, rng: &mut impl Rng) -> PCKey<E> {
    PCKey::<E>::setup(max_degree, rng)
}

pub fn store_params<E: PairingEngine>(pckey: &PCKey<E>, p: &str) -> Result<(), SerializationError> {
    let buffer = File::create(p).unwrap();
    let mut buffer = io::BufWriter::new(buffer);
    pckey.serialize_unchecked(&mut buffer)?;
    buffer.flush()?;
    Ok(())
}

pub fn load_params<E: PairingEngine>(p: &str) -> Result<PCKey<E>, SerializationError> {
    let pckey_file = File::open(p)?;
    let pckey_file = io::BufReader::new(pckey_file);
    let pckey = PCKey::deserialize_unchecked(pckey_file)?;

    return Ok(pckey);
}

pub fn prepare_circuit_params<F: PrimeField, D: Domain<F>, E: PairingEngine>(
    mut cs: Composer<F>,
    pckey: &PCKey<E>,
) -> ProverResult<(Prover<F, D, E>, ProverKey<F, D>, Vec<Commitment<E>>)> {
    let pk = cs.compute_prover_key::<D>().unwrap();
    let mut prover = Prover::<F, D, E>::new(pk.clone());
    let verifier_comms = prover.init_comms(pckey);

    return Ok((prover, pk, verifier_comms));
}

pub fn store_prover_key<F: PrimeField, D: Domain<F>>(
    pk: &ProverKey<F, D>,
    p: &str,
) -> Result<(), SerializationError> {
    let buffer = File::create(p).unwrap();
    let mut buffer = io::BufWriter::new(buffer);
    pk.serialize_unchecked(&mut buffer)?;
    buffer.flush()?;
    Ok(())
}

pub fn load_prover_key<F: PrimeField, D: Domain<F>>(
    p: &str,
) -> Result<ProverKey<F, D>, SerializationError> {
    let pk_file = File::open(p)?;
    let pk_file = io::BufReader::new(pk_file);
    let pk = ProverKey::deserialize_unchecked(pk_file)?;

    return Ok(pk);
}

pub fn store_verifier_comms<E: PairingEngine>(
    verifier_comms: &Vec<Commitment<E>>,
    p: &str,
) -> Result<(), SerializationError> {
    let buffer = File::create(p).unwrap();
    let mut buffer = io::BufWriter::new(buffer);
    verifier_comms.serialize_unchecked(&mut buffer)?;
    buffer.flush()?;
    Ok(())
}

pub fn load_verifier_comms<E: PairingEngine>(
    p: &str,
) -> Result<Vec<Commitment<E>>, SerializationError> {
    let vcomms_file = File::open(p)?;
    let vcomms_file = io::BufReader::new(vcomms_file);
    let vcomms = Vec::deserialize_unchecked(vcomms_file)?;
    return Ok(vcomms);
}
