use std::time::Instant;

use base64::Engine;
use plonk::ark_bn254::{Bn254, Fr};
use plonk::ark_serialize::Write;
use plonk::kzg10::PCKey;
use plonk::Field;

use plonk::{prover::Prover, verifier::Verifier, GeneralEvaluationDomain};
use prover::circuit::openid::OpenIdCircuit;
use prover::parameters::{store_prover_key, store_verifier_comms};
use prover::types::ContractOpenIdInput;
use prover::utils::{bit_location, padding_len};
use prover::utils::{convert_public_inputs, to_0x_hex};
use rand::RngCore;
use sha2::Digest;

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn test_open_id<R: RngCore>(pckey: &PCKey<Bn254>, from_pepper: &[u8], rng: &mut R) {
    let mut pk_openid = None;
    let mut verifier_comms_openid = None;

    let id_tokens = ["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImgzejJzZnFQcU1WQmNKQUJKM1FRQSJ9.eyJuaWNrbmFtZSI6IjEzMjExMTQ2IiwibmFtZSI6IuWNkyDpg5EiLCJwaWN0dXJlIjoiaHR0cHM6Ly9zLmdyYXZhdGFyLmNvbS9hdmF0YXIvZGQ1YjJjM2NjNjU2ZTgzYWYxOTE5NmI4YzA1OGZkYTg_cz00ODAmcj1wZyZkPWh0dHBzJTNBJTJGJTJGY2RuLmF1dGgwLmNvbSUyRmF2YXRhcnMlMkZkZWZhdWx0LnBuZyIsInVwZGF0ZWRfYXQiOiIyMDIzLTAzLTAzVDA4OjQyOjQxLjc5M1oiLCJlbWFpbCI6IjEzMjExMTQ2QGJqdHUuZWR1LmNuIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLndhbGxldC51bmlwYXNzLmlkLyIsImF1ZCI6InZyNktJZ2h4Q3FtRWxwQWQ0VE5EMG5yTUJpQVIzWDJtIiwiaWF0IjoxNjc3ODMyOTYyLCJleHAiOjE2Nzc4MzY1NjIsInN1YiI6ImFwcGxlfDAwMDA2MS4xZTkzNmMwNmUzNWE0OWI5YmJmYzBmMzJjY2FlNTMyZC4xNDMzIiwiYXV0aF90aW1lIjoxNjc3ODMyOTYxLCJhdF9oYXNoIjoiVmpLekRsMEU1SlhyZDRxYkItQm9LZyIsInNpZCI6InBSYWxnWkMwUlhtTng3SjlCRzEtSjBWbGQtbXd4QmpHIiwibm9uY2UiOiJHRllRWE1RVEpoSnRiUWlxdHNsaHR2SEZ1WDRyYzdVZyJ9",
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1NWNjYTZlYzI4MTA2MDJkODBiZWM4OWU0NTZjNDQ5NWQ3NDE4YmIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDc2MjQ5Njg2NjQyLWcwZDQyNTI0ZmhkaXJqZWhvMHQ2bjNjamQ3cHVsbW5zLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTA3NjI0OTY4NjY0Mi1nMGQ0MjUyNGZoZGlyamVobzB0Nm4zY2pkN3B1bG1ucy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNDMzMTY2MDQxMDE2NDA1MzAyMSIsImhkIjoibGF5Mi5kZXYiLCJlbWFpbCI6Inp6aGVuQGxheTIuZGV2IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJqNmQ1aHRFLTF0Mm1Pd2ZQRUFTMXpRIiwibm9uY2UiOiIyYWVjNzM4MSIsImlhdCI6MTY3ODE4OTg4NCwiZXhwIjoxNjc4MTkzNDg0LCJqdGkiOiJkMTRkNTcxYTlhNmRmZmZjNmU2OTM2NjBiNDhlODdlYjIyNTMyYjg5In0",
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI3NDA1MmEyYjY0NDg3NDU3NjRlNzJjMzU5MDk3MWQ5MGNmYjU4NWEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDc2MjQ5Njg2NjQyLWcwZDQyNTI0ZmhkaXJqZWhvMHQ2bjNjamQ3cHVsbW5zLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTA3NjI0OTY4NjY0Mi1nMGQ0MjUyNGZoZGlyamVobzB0Nm4zY2pkN3B1bG1ucy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjExMzA3NTM0MDQ2MjI1NTQ2NzEyMyIsImF0X2hhc2giOiJDOEVrMEdnZFFHY2c0SXZScDEwMnRRIiwibm9uY2UiOiIweGRmMTI1MDA5MGQ3NWQxZDlmM2U1Mzg3Yjg1NGY0ZWJjNWY5MjI5YjAyYzY4OGMwNGRlNjVmZDEwNzQzOTNlOTEiLCJpYXQiOjE2NzUzMzYwODYsImV4cCI6MTY3NTMzOTY4NiwianRpIjoiNjVjZmRjYjQ4MWQ1NjkzNTY3NmQwOTJmNjY0Njg5Y2U0ZTFmYTJmMCJ9",];

    let mut index = -1;
    for id_token in id_tokens {
        index += 1;

        println!("----------------------------------------------------------------");
        println!("test openId-{}", index);

        let circuit = OpenIdCircuit::new(id_token);

        let header_hash = sha2::Sha256::digest(&circuit.header_raw_bytes).to_vec();
        println!("header hash: {}", to_0x_hex(&header_hash));

        let idtoken_hash = sha2::Sha256::digest(id_token).to_vec();
        let payload_pub_match_hash = sha2::Sha256::digest(&circuit.payload_pub_match).to_vec();
        let email_addr_peper_hash = sha2::Sha256::digest(&circuit.email_addr_pepper_bytes).to_vec();

        let mut hash_inputs = vec![];
        hash_inputs.extend(idtoken_hash.clone());
        hash_inputs.extend(email_addr_peper_hash.clone());
        hash_inputs.extend(header_hash);
        hash_inputs.extend(payload_pub_match_hash);

        let (location_id_token_1, location_payload_base64) = bit_location(
            circuit.payload_left_index,
            circuit.payload_base64_len - 1,
            2048,
            1536,
        );
        let (location_id_token_2, location_header_base64) =
            bit_location(0, circuit.header_base64_len - 1, 2048, 512);
        let (location_payload_raw, location_email_addr) = bit_location(
            circuit.email_addrleft_index as u32,
            circuit.email_addrlen as u32,
            1152,
            192,
        );

        hash_inputs.extend(location_id_token_1);
        hash_inputs.extend(location_payload_base64);
        hash_inputs.extend(location_id_token_2);
        hash_inputs.extend(location_header_base64);
        hash_inputs.extend(location_payload_raw);
        hash_inputs.extend(location_email_addr);
        hash_inputs.extend((padding_len(id_token.len() as u32) as u16 / 64).to_be_bytes());
        hash_inputs
            .extend((padding_len(circuit.header_raw_bytes.len() as u32) as u16 / 64).to_be_bytes());
        hash_inputs.extend(
            (padding_len(circuit.payload_raw_bytes.len() as u32) as u16 / 64).to_be_bytes(),
        );
        hash_inputs.extend(
            (padding_len(circuit.email_addr_pepper_bytes.len() as u32) as u16 / 64).to_be_bytes(),
        );

        let mut expected_public_input = sha2::Sha256::digest(&hash_inputs).to_vec();
        expected_public_input[0] = expected_public_input[0] & 0x1f;

        println!("public_input: {}", to_0x_hex(&expected_public_input));
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
        if pk_openid.is_none() {
            pk_openid = Some(
                cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()
                    .unwrap(),
            );

            store_prover_key(pk_openid.as_ref().clone().unwrap(), "email_openid.pk").unwrap();
        }
        println!("[main] compute_prover_key...done");
        let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(
            pk_openid.as_ref().unwrap().clone(),
        );
        println!("[main] init_comms...");
        if verifier_comms_openid.is_none() {
            verifier_comms_openid = Some(prover.init_comms(&pckey));
            store_verifier_comms(
                verifier_comms_openid.as_ref().clone().unwrap(),
                "email_openid.vc",
            )
            .unwrap();
        } else {
            // if already exists, no need "init_comms"
            prover.insert_verifier_comms(verifier_comms_openid.as_ref().unwrap());
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
            verifier_comms_openid.as_ref().unwrap(),
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
        let contract_inputs = ContractOpenIdInput::new(
            circuit.header_raw_bytes,
            circuit.payload_pub_match,
            idtoken_hash.clone(),
            email_addr_peper_hash,
            circuit.header_left_index,
            circuit.header_base64_len,
            circuit.payload_left_index,
            circuit.payload_base64_len,
            circuit.email_addrleft_index,
            circuit.email_addrlen,
            &public_input,
            verifier.domain,
            verifier_comms_openid.as_ref().unwrap(),
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
                "test_data/openid/{}.json",
                to_0x_hex(&idtoken_hash)
            ))
            .unwrap();
        file.write(&serde_json::to_vec_pretty(&contract_inputs).unwrap())
            .unwrap();
        file.flush().unwrap();
    }
}
