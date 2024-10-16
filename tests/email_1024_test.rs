use std::time::Instant;

use plonk::ark_bn254::{Bn254, Fr};
use plonk::ark_serialize::Write;
use plonk::ark_std::test_rng;
use plonk::Field;

use email_parser::parser::parse_email;
use plonk::{prover::Prover, verifier::Verifier, GeneralEvaluationDomain};
use prover::circuit::circuit_1024::Email1024CircuitInput;
use prover::parameters::prepare_generic_params;
use prover::types::ContractInput;
use prover::utils::{bit_location, padding_len};
use prover::utils::{convert_public_inputs, to_0x_hex};
use sha2::Digest;

#[test]
fn test_1024() {
    println!("begin 1024 circuits tests...");
    let mut rng = test_rng();
    // prepare SRS
    let pckey = prepare_generic_params(2097150, &mut rng);

    println!("pckey degree: {}", pckey.max_degree);

    // append 32bytes pepper
    let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    let from_pepper = hex::decode(pepper).unwrap();

    let mut pk_1024 = None;
    let mut verifier_comms_1024 = None;

    let dirs = std::fs::read_dir("test_data/emails").unwrap();

    let mut index = -1;
    for dir in dirs {
        let email_bytes = std::fs::read(dir.unwrap().path()).unwrap();
        let (email_public_inputs, email_private_inputs) =
            parse_email(&email_bytes, from_pepper.to_vec()).unwrap();

        let header_len = email_private_inputs.email_header.len() as u32;
        let addr_len = (email_private_inputs.from_right_index
            - email_private_inputs.from_left_index
            + 1) as u32;
        let from_left_index = email_private_inputs.from_left_index;
        index += 1;
        if email_private_inputs.email_header.len() > 1015 {
            continue;
        }
        println!("----------------------------------------------------------------");
        println!("test circuit 1024-{}", index);

        let circuit = Email1024CircuitInput::new(email_private_inputs).unwrap();
        println!("[main] circuit construct finish");

        let (bit_location_a, bit_location_b) =
            bit_location(from_left_index as u32, addr_len, 1024, 192);

        println!(
            "bit_loaction_a: {}, bit_location_b: {}",
            hex::encode(&bit_location_a),
            hex::encode(&bit_location_b)
        );

        let mut sha256_input: Vec<u8> = vec![];
        sha256_input.extend(&email_public_inputs.header_hash);
        sha256_input.extend(&email_public_inputs.from_hash);
        sha256_input.extend(bit_location_a);
        sha256_input.extend(bit_location_b);
        sha256_input.extend(sha2::Sha256::digest(&circuit.email_header_pub_match).to_vec());
        sha256_input.extend((padding_len(header_len) as u16 / 64).to_be_bytes());
        sha256_input.extend((padding_len(addr_len + 32) as u16 / 64).to_be_bytes());

        let mut expected_public_input = sha2::Sha256::digest(&sha256_input).to_vec();
        expected_public_input[0] &= 0x1f;
        println!(
            "expected_public_input: {}",
            to_0x_hex(&expected_public_input)
        );
        let expected_public_input = vec![Fr::from_be_bytes_mod_order(&expected_public_input)];
        let mut cs = circuit.synthesize();
        println!("[main] synthesize finish");
        let public_input = cs.compute_public_input();
        println!(
            "[main] public input: {:?}",
            convert_public_inputs(&public_input)
        );

        if expected_public_input != public_input {
            panic!("Public input error")
        }

        println!("[main] time start:");
        let start = Instant::now();
        println!("[main] compute_prover_key...");
        if pk_1024.is_none() {
            pk_1024 = Some(
                cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()
                    .unwrap(),
            );
        }
        println!("[main] compute_prover_key...done");
        let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(
            pk_1024.as_ref().unwrap().clone(),
        );
        println!("[main] init_comms...");
        if verifier_comms_1024.is_none() {
            verifier_comms_1024 = Some(prover.init_comms(&pckey));
        } else {
            // if already exists, no need "init_comms"
            prover.insert_verifier_comms(verifier_comms_1024.as_ref().unwrap());
        }

        println!("[main] init_comms...done");
        println!("[main] time cost: {:?} ms", start.elapsed().as_millis()); // ms

        let prove_start = Instant::now();
        println!("[main] prove start:");
        let proof = prover.prove(&mut cs, &pckey, &mut rng).unwrap();
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
            verifier_comms_1024.as_ref().unwrap(),
        );
        let sha256_of_srs = pckey.sha256_of_srs();
        let ok = verifier.verify(&pckey.vk, &proof, &sha256_of_srs);
        assert!(ok);
        println!("[main] verify finish:");
        println!(
            "[main] verify time cost: {:?} ms",
            verify_start.elapsed().as_millis()
        ); // ms

        let header_pub_match = circuit.email_header_pub_match.clone();
        let header_hash = email_public_inputs.header_hash.clone();
        let addr_hash = email_public_inputs.from_hash.clone();

        // gen contract inputs data for test
        let contract_inputs = ContractInput::new(
            header_hash,
            addr_hash,
            header_pub_match,
            header_len,
            from_left_index as u32,
            addr_len,
            &public_input,
            verifier.domain,
            verifier_comms_1024.as_ref().unwrap(),
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
                "test_data/inputs_1024/{}.json",
                to_0x_hex(&email_public_inputs.header_hash)
            ))
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&contract_inputs).unwrap())
            .unwrap();
        file.flush().unwrap();
    }
}
