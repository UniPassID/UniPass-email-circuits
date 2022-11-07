use std::time::Instant;

use plonk::ark_bn254::{Bn254, Fr};
use plonk::ark_serialize::{SerializationError, Write};
use plonk::ark_std::test_rng;

use email_parser::parser::parse_email;
use plonk::{prover::Prover, verifier::Verifier, GeneralEvaluationDomain};
use prover::parameters::{store_params, store_prover_key, store_verifier_comms};
use prover::{
    circuit::{circuit_1024::Email1024CircuitInput, circuit_2048::Email2048CircuitInput},
    parameters::prepare_generic_params,
    types::ContractInput,
    utils::{convert_public_inputs, to_0x_hex},
};

fn main() -> Result<(), SerializationError> {
    let mut rng = test_rng();
    // prepare SRS
    let pckey = prepare_generic_params(524300, &mut rng);

    store_params(&pckey, "email.pckey").unwrap();
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
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(format!(
                    "test_data/privates/{}.json",
                    to_0x_hex(&email_public_inputs.header_hash)
                ))
                .unwrap();
            file.write(&serde_json::to_vec_pretty(&email_private_inputs).unwrap())
                .unwrap();
            file.flush().unwrap();

            index += 1;
            if email_private_inputs.email_header.len() > 1024 {
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

            // gen contract inputs data for test
            let contract_inputs = ContractInput::new(
                circuit.from_left_index,
                circuit.from_len,
                circuit.email_header_pub_match,
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

            // if private_inputs.email_header.len() < 1024 {
            //     continue;
            // }
            println!("----------------------------------------------------------------");
            println!("Test circuit 2048-{}", index);

            let circuit = Email2048CircuitInput::new(email_private_inputs).unwrap();
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

            // gen contract inputs data for test
            let contract_inputs = ContractInput::new(
                circuit.from_left_index,
                circuit.from_len,
                circuit.email_header_pub_match,
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

    Ok(())
}
