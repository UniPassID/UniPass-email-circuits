use crate::Field;
use ark_ec::PairingEngine;
use ark_poly_commit::kzg10::Commitment;
use ark_serialize::*;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F: Field, E: PairingEngine> {
    // witnesses
    pub commitments1: Vec<Commitment<E>>,
    // "s"
    pub commitment2: Commitment<E>,
    // "z".to_string(), "z_lookup", "z_substring"
    pub commitments3: Vec<Commitment<E>>,
    // "t"
    pub commitments4: Vec<Commitment<E>>,

    pub evaluations: Vec<F>,
    pub evaluations_alt_point: Vec<F>,

    // polynomial commitment proof at zeta
    pub Wz_pi: Commitment<E>,
    // polynomial commitment proof at zeta_omega
    pub Wzw_pi: Commitment<E>,
}
