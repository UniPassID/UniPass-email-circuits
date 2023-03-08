use std::time::Instant;

use plonk::ark_bn254::{Bn254, Fr};
use plonk::ark_serialize::Write;
use plonk::kzg10::PCKey;
use plonk::Field;

use email_parser::parser::parse_email;
use plonk::{prover::Prover, verifier::Verifier, GeneralEvaluationDomain};
use prover::circuit::circuit_2048_triple::Email2048TripleCircuitInput;
use prover::parameters::store_verifier_comms;
use prover::types::ContractTripleInput;
use prover::utils::{bit_location, padding_len};
use prover::utils::{convert_public_inputs, to_0x_hex};
use rand::RngCore;
use sha2::Digest;

pub fn test_2048tri<R: RngCore>(pckey: &PCKey<Bn254>, from_pepper: &[u8], rng: &mut R) {
    let mut pk_2048 = None;
    let mut verifier_comms_2048 = None;

    let dirs = std::fs::read_dir("test_data/emails").unwrap();

    let mut all_email_public_inputs = vec![];
    let mut all_email_private_inputs = vec![];
    for dir in dirs {
        let email_bytes = std::fs::read(dir.unwrap().path()).unwrap();
        let (email_public_inputs, email_private_inputs) =
            parse_email(&email_bytes, from_pepper.to_vec()).unwrap();

        all_email_public_inputs.push(email_public_inputs);
        all_email_private_inputs.push(email_private_inputs);
    }
    println!("----------------------------------------------------------------");
    println!("Test circuit 2048triple");

    let circuit =
        Email2048TripleCircuitInput::new(all_email_private_inputs[0..3].to_vec()).unwrap();
    println!("[main] circuit construct finish");

    let mut sha256_input: Vec<u8> = vec![];
    for (i, (email_public_inputs, email_private_inputs)) in all_email_public_inputs
        .iter()
        .zip(&all_email_private_inputs)
        .enumerate()
    {
        let header_len = email_private_inputs.email_header.len() as u32;
        let addr_len = (email_private_inputs.from_right_index
            - email_private_inputs.from_left_index
            + 1) as u32;
        let from_left_index = email_private_inputs.from_left_index;
        let (bit_location_a, bit_location_b) =
            bit_location(from_left_index as u32, addr_len, 2048, 192);
        let mut r: Vec<u8> = vec![];
        r.extend(&email_public_inputs.header_hash);
        r.extend(&email_public_inputs.from_hash);
        r.extend(&bit_location_a);
        r.extend(&bit_location_b);
        sha256_input.extend(sha2::Sha256::digest(&r.to_vec()));
        sha256_input.extend(sha2::Sha256::digest(&circuit.email_header_pub_matches[i]).to_vec());
        sha256_input.extend((padding_len(header_len) as u16 / 64).to_be_bytes());
        sha256_input.extend((padding_len(addr_len + 32) as u16 / 64).to_be_bytes());
    }

    let mut expected_public_input = sha2::Sha256::digest(&sha256_input).to_vec();
    expected_public_input[0] = expected_public_input[0] & 0x1f;
    println!(
        "expected_public_input: {}",
        to_0x_hex(&expected_public_input)
    );
    let expected_public_input = vec![Fr::from_be_bytes_mod_order(&expected_public_input)];

    let mut cs = circuit.synthesize();
    println!("[main] synthesize finish");

    let public_input = cs.compute_public_input();
    println!("cs.size() {}", cs.size());

    if expected_public_input != public_input {
        panic!("Public input error")
    }

    println!(
        "[main] public input: {:?}",
        convert_public_inputs(&public_input)
    );

    println!("[main] time start:");
    let start = Instant::now();
    println!("[main] compute_prover_key...");
    if pk_2048.is_none() {
        pk_2048 = Some(
            cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()
                .unwrap(),
        );
        // store_prover_key(pk_2048.as_ref().clone().unwrap(), "email_2048.pk").unwrap();
    }

    println!("[main] compute_prover_key...done");
    let mut prover =
        Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(pk_2048.as_ref().unwrap().clone());
    println!("prover.domain_size() {}", prover.domain_size());

    println!("[main] init_comms...");
    if verifier_comms_2048.is_none() {
        verifier_comms_2048 = Some(prover.init_comms(&pckey));

        store_verifier_comms(
            verifier_comms_2048.as_ref().clone().unwrap(),
            "email_2048triple.vc",
        )
        .unwrap();
    } else {
        // if already exists, no need "init_comms"
        prover.insert_verifier_comms(verifier_comms_2048.as_ref().unwrap());
    }

    println!("[main] init_comms...done");
    println!("[main] time cost: {:?} ms", start.elapsed().as_millis()); // ms

    let prove_start = Instant::now();
    println!("[main] prove start:");
    let proof = prover.prove(&mut cs, &pckey, rng).unwrap();
    println!("[main] prove finish:");
    println!(
        "[main] prove time cost: {:?} ms",
        prove_start.elapsed().as_millis()
    ); // ms

    println!("[main] verify start:");
    let verify_start = Instant::now();
    let mut verifier = Verifier::new(
        &prover,
        &public_input,
        verifier_comms_2048.as_ref().unwrap(),
    );
    let sha256_of_srs = pckey.sha256_of_srs();
    let ok = verifier.verify(&pckey.vk, &proof, &sha256_of_srs);
    assert!(ok);
    println!("[main] verify finish:");
    println!(
        "[main] verify time cost: {:?} ms",
        verify_start.elapsed().as_millis()
    ); // ms

    // gen contract inputs data for test
    let contract_inputs = ContractTripleInput::new(
        all_email_public_inputs
            .iter()
            .map(|a| a.header_hash.clone())
            .collect(),
        all_email_public_inputs
            .iter()
            .map(|a| a.from_hash.clone())
            .collect(),
        circuit.email_header_pub_matches,
        all_email_private_inputs
            .iter()
            .map(|a| a.email_header.len() as u32)
            .collect(),
        circuit.from_left_indexes,
        circuit.from_lens,
        &public_input,
        verifier.domain,
        verifier_comms_2048.as_ref().unwrap(),
        pckey.vk.beta_h,
        &proof,
        &sha256_of_srs,
    );

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(format!(
            "test_data/inputs_2048triple/tri_{}.json",
            to_0x_hex(&all_email_public_inputs[0].header_hash)
        ))
        .unwrap();
    file.write(&serde_json::to_vec_pretty(&contract_inputs).unwrap())
        .unwrap();
    file.flush().unwrap();
}
