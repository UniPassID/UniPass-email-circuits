use std::time::Instant;

use plonk::ark_bn254::{Bn254, Fr};
use plonk::ark_serialize::{SerializationError, Write};
use plonk::ark_std::test_rng;

use email_parser::parser::parse_email;
use plonk::{prover::Prover, verifier::Verifier, GeneralEvaluationDomain};
use prover::circuit::circuit_2048_triple::Email2048TripleCircuitInput;
use prover::parameters::{store_params, store_prover_key, store_verifier_comms};
use prover::types::ContractTripleInput;
use prover::{
    circuit::{circuit_1024::Email1024CircuitInput, circuit_2048::Email2048CircuitInput},
    parameters::prepare_generic_params,
    types::ContractInput,
    utils::{convert_public_inputs, to_0x_hex},
};

fn main() -> Result<(), SerializationError> {
    let mut rng = test_rng();
    // prepare SRS
    let pckey = prepare_generic_params(2098000, &mut rng);

    store_params(&pckey, "emailtriple.pckey").unwrap();
    // append 32bytes pepper
    let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    let from_pepper = hex::decode(pepper).unwrap();

    {
        let mut pk_1024 = None;
        let mut verifier_comms_1024 = None;

        let dirs = std::fs::read_dir("test_data/emails").unwrap();

        let mut index = -1;
        for dir in dirs {
            let email_bytes = std::fs::read(dir.unwrap().path()).unwrap();
            let (email_public_inputs, email_private_inputs) =
                parse_email(&email_bytes, from_pepper.clone()).unwrap();

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
            let mut cs = circuit.synthesize();
            println!("[main] synthesize finish");

            let public_input = cs.compute_public_input();

            println!(
                "[main] public input: {:?}",
                convert_public_inputs(&public_input)
            );

            println!("[main] time start:");
            let start = Instant::now();
            println!("[main] compute_prover_key...");
            if pk_1024.is_none() {
                pk_1024 = Some(
                    cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()
                        .unwrap(),
                );

                store_prover_key(pk_1024.as_ref().clone().unwrap(), "email_1024.pk").unwrap();
            }
            println!("[main] compute_prover_key...done");
            let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(
                pk_1024.as_ref().unwrap().clone(),
            );
            println!("[main] init_comms...");
            if verifier_comms_1024.is_none() {
                verifier_comms_1024 = Some(prover.init_comms(&pckey));
                store_verifier_comms(
                    verifier_comms_1024.as_ref().clone().unwrap(),
                    "email_1024.vc",
                )
                .unwrap();
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
                addr_len as u32,
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
            file.write(&serde_json::to_vec_pretty(&contract_inputs).unwrap())
                .unwrap();
            file.flush().unwrap();
        }
    }

    {
        let mut pk_2048 = None;
        let mut verifier_comms_2048 = None;

        let mut index = -1;

        let dirs = std::fs::read_dir("test_data/emails").unwrap();
        for dir in dirs {
            let email_bytes = std::fs::read(dir.unwrap().path()).unwrap();
            let (email_public_inputs, email_private_inputs) =
                parse_email(&email_bytes, from_pepper.clone()).unwrap();
            index += 1;

            let header_len = email_private_inputs.email_header.len() as u32;

            println!("----------------------------------------------------------------");
            println!("Test circuit 2048-{}", index);

            let circuit = Email2048CircuitInput::new(email_private_inputs).unwrap();
            println!("[main] circuit construct finish");
            let mut cs = circuit.synthesize();
            println!("[main] synthesize finish");

            let public_input = cs.compute_public_input();
            println!("cs.size() {}", cs.size());

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
                store_prover_key(pk_2048.as_ref().clone().unwrap(), "email_2048.pk").unwrap();
            }

            println!("[main] compute_prover_key...done");
            let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(
                pk_2048.as_ref().unwrap().clone(),
            );
            println!("prover.domain_size() {}", prover.domain_size());

            println!("[main] init_comms...");
            if verifier_comms_2048.is_none() {
                verifier_comms_2048 = Some(prover.init_comms(&pckey));

                store_verifier_comms(
                    verifier_comms_2048.as_ref().clone().unwrap(),
                    "email_2048.vc",
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

            let header_hash = email_public_inputs.header_hash.clone();
            let addr_hash = email_public_inputs.from_hash.clone();

            // gen contract inputs data for test
            let contract_inputs = ContractInput::new(
                header_hash,
                addr_hash,
                circuit.email_header_pub_match,
                header_len,
                circuit.from_left_index,
                circuit.from_len,
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
                    "test_data/inputs_2048/{}.json",
                    to_0x_hex(&email_public_inputs.header_hash)
                ))
                .unwrap();
            file.write(&serde_json::to_vec_pretty(&contract_inputs).unwrap())
                .unwrap();
            file.flush().unwrap();
        }
    }

    // test triple-circuit
    {
        let mut pk_2048 = None;
        let mut verifier_comms_2048 = None;

        let dirs = std::fs::read_dir("test_data/emails").unwrap();

        let mut all_email_public_inputs = vec![];
        let mut all_email_private_inputs = vec![];
        for dir in dirs {
            let email_bytes = std::fs::read(dir.unwrap().path()).unwrap();
            let (email_public_inputs, email_private_inputs) =
                parse_email(&email_bytes, from_pepper.clone()).unwrap();

            all_email_public_inputs.push(email_public_inputs);
            all_email_private_inputs.push(email_private_inputs);
        }
        println!("----------------------------------------------------------------");
        println!("Test circuit 2048triple");

        let circuit =
            Email2048TripleCircuitInput::new(all_email_private_inputs[0..3].to_vec()).unwrap();
        println!("[main] circuit construct finish");
        let mut cs = circuit.synthesize();
        println!("[main] synthesize finish");

        let public_input = cs.compute_public_input();
        println!("cs.size() {}", cs.size());

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
        let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(
            pk_2048.as_ref().unwrap().clone(),
        );
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
            all_email_public_inputs[0].header_hash.clone(),
            all_email_public_inputs[0].from_hash.clone(),
            circuit.first_email_header_pub_match,
            all_email_private_inputs[0].email_header.len() as u32,
            circuit.first_from_left_index,
            circuit.first_from_len,
            all_email_public_inputs[1].header_hash.clone(),
            all_email_public_inputs[1].from_hash.clone(),
            circuit.second_email_header_pub_match,
            all_email_private_inputs[1].email_header.len() as u32,
            circuit.second_from_left_index,
            circuit.second_from_len,
            all_email_public_inputs[2].header_hash.clone(),
            all_email_public_inputs[2].from_hash.clone(),
            circuit.third_email_header_pub_match,
            all_email_private_inputs[2].email_header.len() as u32,
            circuit.third_from_left_index,
            circuit.third_from_len,
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

    Ok(())
}
