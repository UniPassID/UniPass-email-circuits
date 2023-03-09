use plonk::ark_serialize::SerializationError;
use plonk::ark_std::test_rng;

use prover::parameters::{load_params, store_params};

use crate::circuit_1024::test_1024;
use crate::circuit_2048::test_2048;
use crate::circuit_2048_triple::test_2048tri;
use crate::openid::test_open_id;

pub mod circuit_1024;
pub mod circuit_2048;
pub mod circuit_2048_triple;
pub mod openid;

fn main() -> Result<(), SerializationError> {
    let mut rng = test_rng();
    // prepare SRS
    let pckey = load_params("email.pckey").unwrap();

    println!("pckey degree: {}", pckey.max_degree());

    store_params(&pckey, "email.pckey").unwrap();

    // append 32bytes pepper
    let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    let from_pepper = hex::decode(pepper).unwrap();

    test_open_id(&pckey, &from_pepper, &mut rng);
    test_1024(&pckey, &from_pepper, &mut rng);
    test_2048(&pckey, &from_pepper, &mut rng);
    test_2048tri(&pckey, &from_pepper, &mut rng);
    Ok(())
}
