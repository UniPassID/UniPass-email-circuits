use plonk::{
    ark_bn254::Fr,
    ark_std::Zero,
    sha256::{
        sha256_collect_8_outputs_to_field, sha256_no_padding_words_var,
        sha256_no_padding_words_var_fixed_length, Sha256Word,
    },
    Composer,
};

use crate::utils::padding_bytes;

use super::base64::base64url_encode_gadget;

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub struct OpenIdCircuit {
    pub id_token_bytes: Vec<u8>,
    pub header_raw_bytes: Vec<u8>,
    pub payload_raw_bytes: Vec<u8>,

    pub email_addr_pepper_bytes: Vec<u8>,
    pub payload_pub_match: Vec<u8>,

    pub header_base64_len: u32,
    pub payload_left_index: u32,
    pub payload_base64_len: u32,
    pub from_left_index: u32,
    pub from_len: u32,
}

impl OpenIdCircuit {
    pub fn synthesize(&self) -> Composer<Fr> {
        let mut cs = Composer::new(5, false);

        const PAYLOAD_RAW_MAX_LEN: usize = 1152;
        // (PAYLOAD_RAW_MAX_LEN / 3) * 4
        const PAYLOAD_BASE64_MAX_LEN: usize = 1536;

        const HEADER_RAW_MAX_LEN: usize = 384;
        const HEADER_BASE64_MAX_LEN: usize = 512;

        const ID_TOKEN_MAX_LEN: usize = 2048;
        const EMAIL_ADDR_MAX_LEN: usize = 192;

        // get the id_token hash
        let id_token_padding_bytes = padding_bytes(&self.id_token_bytes);
        let id_token_padding_len = (id_token_padding_bytes.len() / 64) as u32;

        let mut id_token_padding_vars = vec![];
        for e in &id_token_padding_bytes {
            id_token_padding_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = id_token_padding_vars.len();
        for _ in n..ID_TOKEN_MAX_LEN {
            id_token_padding_vars.push(cs.alloc(Fr::zero()));
        }

        // num of 512bits. we need the index to output correct sha256.
        let id_token_data_len = cs.alloc(Fr::from(id_token_padding_len));

        let mut sha256_id_token_data = vec![];
        for vs in id_token_padding_vars.chunks(4) {
            // "Sha256Word" is the type we need in the sha256, each contain 32bits
            sha256_id_token_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }

        // get the id_token hash
        let id_token_hash = sha256_no_padding_words_var(
            &mut cs,
            &sha256_id_token_data,
            id_token_data_len,
            ID_TOKEN_MAX_LEN * 8 / 512,
        )
        .unwrap();

        // get the email_addr hash
        let email_addr_pepper_bytes_padding = padding_bytes(&self.email_addr_pepper_bytes);
        let from_padding_len = (email_addr_pepper_bytes_padding.len() / 64) as u32;
        // alloc variables for "b"
        let mut email_addr_pepper_vars = vec![];
        for e in &email_addr_pepper_bytes_padding {
            email_addr_pepper_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = email_addr_pepper_vars.len();
        // padding "email_addr" to EMAIL_ADDR_MAX_LENs
        for _ in n..EMAIL_ADDR_MAX_LEN {
            email_addr_pepper_vars.push(cs.alloc(Fr::zero()));
        }

        // num of 512bits. we need the index to output correct sha256.
        let email_addr_pepper_data_len = cs.alloc(Fr::from(from_padding_len));

        // cal sha256 of b_pepper
        let mut sha256_addr_data = vec![];
        for vs in email_addr_pepper_vars.chunks(4) {
            sha256_addr_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }
        let email_addr_pepper_hash = sha256_no_padding_words_var(
            &mut cs,
            &sha256_addr_data,
            email_addr_pepper_data_len,
            EMAIL_ADDR_MAX_LEN * 8 / 512,
        )
        .unwrap();

        // calculate payload base64 encode
        let payload_raw_bytes_padding = padding_bytes(&self.payload_raw_bytes);
        let mut payload_raw_vars = vec![];
        for e in &payload_raw_bytes_padding {
            payload_raw_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = payload_raw_vars.len();
        for _ in n..PAYLOAD_RAW_MAX_LEN {
            payload_raw_vars.push(cs.alloc(Fr::zero()));
        }
        let payload_encoded_vars =
            base64url_encode_gadget(&mut cs, &payload_raw_vars, PAYLOAD_RAW_MAX_LEN).unwrap();

        // construct header_pub_match and calculate hash
        let payload_pub_match_padding = padding_bytes(&self.payload_pub_match);
        let payload_pub_match_padding_len = (payload_pub_match_padding.len() / 64) as u32;

        let mut payload_pub_match_vars = vec![];
        for e in &payload_pub_match_padding {
            payload_pub_match_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = payload_pub_match_vars.len();
        for _ in n..PAYLOAD_RAW_MAX_LEN {
            payload_pub_match_vars.push(cs.alloc(Fr::zero()));
        }

        // num of 512bits. we need the index to output correct sha256.
        let payload_pub_match_data_len = cs.alloc(Fr::from(payload_pub_match_padding_len));

        let mut sha256_payload_pub_match_data = vec![];
        for vs in payload_pub_match_vars.chunks(4) {
            // "Sha256Word" is the type we need in the sha256, each contain 32bits
            sha256_payload_pub_match_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }

        // get the header hash
        let payload_pub_match_hash = sha256_no_padding_words_var(
            &mut cs,
            &sha256_payload_pub_match_data,
            payload_pub_match_data_len,
            PAYLOAD_RAW_MAX_LEN * 8 / 512,
        )
        .unwrap();

        // calculate header base64 encode and hash
        let header_raw_bytes_padding = padding_bytes(&self.header_raw_bytes);
        let header_raw_bytes_padding_len = (header_raw_bytes_padding.len() / 64) as u32;

        let mut header_raw_vars = vec![];
        for e in &self.header_raw_bytes {
            header_raw_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = header_raw_vars.len();
        for _ in n..HEADER_RAW_MAX_LEN {
            header_raw_vars.push(cs.alloc(Fr::zero()));
        }

        // num of 512bits. we need the index to output correct sha256.
        let header_raw_data_len = cs.alloc(Fr::from(header_raw_bytes_padding_len));

        let mut sha256_header_raw_data = vec![];
        for vs in header_raw_vars.chunks(4) {
            // "Sha256Word" is the type we need in the sha256, each contain 32bits
            sha256_header_raw_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }

        // get the header hash
        let header_hash = sha256_no_padding_words_var(
            &mut cs,
            &sha256_header_raw_data,
            header_raw_data_len,
            HEADER_RAW_MAX_LEN * 8 / 512,
        )
        .unwrap();

        let header_encoded_vars =
            base64url_encode_gadget(&mut cs, &header_raw_vars, HEADER_RAW_MAX_LEN).unwrap();

        // start index of the encoded payload
        let l = cs.alloc(Fr::from(self.payload_left_index));
        // length of the encoded payload
        let m = cs.alloc(Fr::from(self.payload_base64_len));
        let (bit_location_id_token_1, bit_location_payload_base64) = cs
            .gen_bit_location_for_substr(l, m, ID_TOKEN_MAX_LEN, PAYLOAD_BASE64_MAX_LEN)
            .unwrap();

        let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &id_token_hash).unwrap();
        // private substring check.
        cs.add_substring_mask_poly_return_words(
            &id_token_padding_vars,
            &payload_encoded_vars,
            &bit_location_id_token_1,
            &bit_location_payload_base64,
            mask_r,
            l,
            m,
            ID_TOKEN_MAX_LEN,
            PAYLOAD_BASE64_MAX_LEN,
        )
        .unwrap();

        // start index of the email address
        let l = cs.alloc(Fr::from(0));
        // length of the email address
        let m = cs.alloc(Fr::from(self.header_base64_len));

        let (bit_location_id_token_2, bit_location_header_base64) = cs
            .gen_bit_location_for_substr(l, m, ID_TOKEN_MAX_LEN, HEADER_BASE64_MAX_LEN)
            .unwrap();

        let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &header_hash).unwrap();
        // private substring check.
        cs.add_substring_mask_poly_return_words(
            &id_token_padding_vars,
            &header_encoded_vars,
            &bit_location_id_token_2,
            &bit_location_header_base64,
            mask_r,
            l,
            m,
            ID_TOKEN_MAX_LEN,
            HEADER_BASE64_MAX_LEN,
        )
        .unwrap();

        // start index of the email address
        let l = cs.alloc(Fr::from(self.from_left_index));
        // length of the email address
        let m = cs.alloc(Fr::from(self.from_len));

        let (bit_location_payload_raw, bit_location_email_addr) = cs
            .gen_bit_location_for_substr(l, m, PAYLOAD_RAW_MAX_LEN, EMAIL_ADDR_MAX_LEN)
            .unwrap();

        let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &email_addr_pepper_hash).unwrap();
        // private substring check.
        cs.add_substring_mask_poly_return_words(
            &payload_raw_vars,
            &email_addr_pepper_vars,
            &bit_location_payload_raw,
            &bit_location_email_addr,
            mask_r,
            l,
            m,
            PAYLOAD_RAW_MAX_LEN,
            EMAIL_ADDR_MAX_LEN,
        )
        .unwrap();

        let output_words_id_token_1 = cs
            .collect_bit_location_for_sha256(ID_TOKEN_MAX_LEN, &bit_location_id_token_1)
            .unwrap();
        let output_words_payload_base64 = cs
            .collect_bit_location_for_sha256(PAYLOAD_BASE64_MAX_LEN, &bit_location_payload_base64)
            .unwrap();

        let output_words_id_token_2 = cs
            .collect_bit_location_for_sha256(ID_TOKEN_MAX_LEN, &bit_location_id_token_2)
            .unwrap();
        let output_words_header_base64 = cs
            .collect_bit_location_for_sha256(HEADER_BASE64_MAX_LEN, &bit_location_header_base64)
            .unwrap();

        let output_words_payload_raw = cs
            .collect_bit_location_for_sha256(PAYLOAD_RAW_MAX_LEN, &bit_location_payload_raw)
            .unwrap();
        let output_words_email_addr = cs
            .collect_bit_location_for_sha256(EMAIL_ADDR_MAX_LEN, &bit_location_email_addr)
            .unwrap();

        // 8512bit, id_token_hash|email_hash|header_hash|payload_pubmatch_hash|bit_location_id_token_1|bit_location_payload_base64|
        // bit_location_id_token_2|bit_location_header_base64|bit_location_payload_raw|bit_location_email_addr
        let mut sha256_all_public_data = vec![];
        for wd in id_token_hash {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in email_addr_pepper_hash {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in header_hash {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in payload_pub_match_hash {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in output_words_id_token_1 {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in output_words_payload_base64 {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in output_words_id_token_2 {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in output_words_header_base64 {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in output_words_payload_raw {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in output_words_email_addr {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }

        // padding (128bits + 64bits)
        {
            let pad_value = Fr::from(1u64 << 31);
            let tmp_var = cs.alloc(pad_value);
            cs.enforce_constant(tmp_var, pad_value);
            let word = Sha256Word {
                var: tmp_var,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
            for _ in 0..4 {
                let word = Sha256Word {
                    var: Composer::<Fr>::null(),
                    hvar: Composer::<Fr>::null(),
                    lvar: Composer::<Fr>::null(),
                    hvar_spread: Composer::<Fr>::null(),
                    lvar_spread: Composer::<Fr>::null(),
                };
                sha256_all_public_data.push(word);
            }
            let pad_value = Fr::from(8512u64);
            let tmp_var = cs.alloc(pad_value);
            cs.enforce_constant(tmp_var, pad_value);
            let word = Sha256Word {
                var: tmp_var,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }

        let all_public_hash =
            sha256_no_padding_words_var_fixed_length(&mut cs, &sha256_all_public_data, 17).unwrap();

        let public_inputs_hash =
            sha256_collect_8_outputs_to_field(&mut cs, &all_public_hash).unwrap();

        cs.set_variable_public_input(public_inputs_hash);

        // pub match "a"
        // public string match.
        cs.add_public_match_no_custom_gate(
            &payload_raw_vars,
            &payload_pub_match_vars,
            PAYLOAD_RAW_MAX_LEN,
        );

        cs.set_variable_public_input(mask_r);

        cs
    }
}

#[cfg(test)]
mod tests {

    use std::time::Instant;

    use crate::{circuit::openid::find_subsequence, utils::to_0x_hex};

    use super::OpenIdCircuit;
    use base64::Engine;
    use plonk::{
        ark_bn254::{self, Fr},
        ark_std::test_rng,
        kzg10::PCKey,
        prover,
        verifier::Verifier,
        Composer, Error, GeneralEvaluationDomain,
    };
    use sha2::Digest;

    fn test_prove_verify(cs: &mut Composer<Fr>) -> Result<(), Error> {
        println!();
        let public_input = cs.compute_public_input();
        println!("cs.size() {}", cs.size());
        println!("cs.table_size() {}", cs.table_size());
        println!("cs.sorted_size() {}", cs.sorted_size());

        let rng = &mut test_rng();

        println!("time start:");
        let start = Instant::now();
        println!("compute_prover_key...");
        let pk = cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()?;
        println!("pk.domain_size() {}", pk.domain_size());
        println!("compute_prover_key...done");
        let pckey = PCKey::<ark_bn254::Bn254>::setup(pk.domain_size() + pk.program_width + 6, rng);
        println!("pckey.max_degree() {}", pckey.max_degree());
        let mut prover =
            prover::Prover::<Fr, GeneralEvaluationDomain<Fr>, ark_bn254::Bn254>::new(pk);

        println!("init_comms...");
        let verifier_comms = prover.init_comms(&pckey);
        println!("init_comms...done");
        println!("time cost: {:?} ms", start.elapsed().as_millis()); // ms
        let mut verifier = Verifier::new(&prover, &public_input, &verifier_comms);

        println!("prove start:");
        let start = Instant::now();
        let proof = prover.prove(cs, &pckey, rng)?;
        println!("prove time cost: {:?} ms", start.elapsed().as_millis()); // ms

        let sha256_of_srs = pckey.sha256_of_srs();
        println!("verify start:");
        let start = Instant::now();
        let res = verifier.verify(&pckey.vk, &proof, &sha256_of_srs);
        println!("verify result: {}", res);
        assert!(res);
        println!("verify time cost: {:?} ms", start.elapsed().as_millis()); // ms

        Ok(())
    }

    #[test]
    fn test_openid_circuit() {
        let id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI3NDA1MmEyYjY0NDg3NDU3NjRlNzJjMzU5MDk3MWQ5MGNmYjU4NWEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDc2MjQ5Njg2NjQyLWcwZDQyNTI0ZmhkaXJqZWhvMHQ2bjNjamQ3cHVsbW5zLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTA3NjI0OTY4NjY0Mi1nMGQ0MjUyNGZoZGlyamVobzB0Nm4zY2pkN3B1bG1ucy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjExMzA3NTM0MDQ2MjI1NTQ2NzEyMyIsImF0X2hhc2giOiJDOEVrMEdnZFFHY2c0SXZScDEwMnRRIiwibm9uY2UiOiIweGRmMTI1MDA5MGQ3NWQxZDlmM2U1Mzg3Yjg1NGY0ZWJjNWY5MjI5YjAyYzY4OGMwNGRlNjVmZDEwNzQzOTNlOTEiLCJpYXQiOjE2NzUzMzYwODYsImV4cCI6MTY3NTMzOTY4NiwianRpIjoiNjVjZmRjYjQ4MWQ1NjkzNTY3NmQwOTJmNjY0Njg5Y2U0ZTFmYTJmMCJ9";
        let _signature = "aKL5QNevcjvM9AYJTCTviiuZOmMs2PkJjw3KWMqNpYy3jvjRe3nchkj367TNZ7XQ7c1UNnfqG9VUXnZq3nhC8NN1iSaLtMySZuggAtRvcbVrdVtEfsCwEqDm2GXZL2B12HSXMynPdhod_AXZ5dGblK2eDue4NT3q5acgPqW_XmmDcUd5Pf-Vb5x5x8pk-wWbLtSKXMITDfR8WLGPFdBjjIZWL-ttiLcL-TClGegM51rN9Ps2BYgMfXJTvdQz66QnI54j1EJt-8NdI7EtXtZdBesemLw4Q9xsskZUe2bvcdcEO89O2CLxT2m0mz60Nrz06zyaeY2fOBq2YKddkrwgOA";
        let id_tokens: Vec<_> = id_token.split('.').collect();
        let header_base64_bytes = id_tokens[0].as_bytes().to_vec();
        let payload_base64_bytes = id_tokens[1].as_bytes().to_vec();

        let payload_left_index = (header_base64_bytes.len() + 1) as u32;
        let payload_base64_len = payload_base64_bytes.len() as u32;
        let header_base64_len = header_base64_bytes.len() as u32;

        let idtoken_hash = sha2::Sha256::digest(id_token).to_vec();

        println!("header_hash: {}", to_0x_hex(&idtoken_hash));
        println!(
            "header len: {}, payload len: {}",
            header_base64_bytes.len(),
            payload_base64_bytes.len()
        );

        let base64url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload_raw_bytes = base64url_engine.decode(&payload_base64_bytes).unwrap();
        let header_raw_bytes = base64url_engine.decode(&header_base64_bytes).unwrap();

        println!("payload: {}", String::from_utf8_lossy(&payload_raw_bytes));

        let needle = br#""sub":""#;
        let from_left_index = find_subsequence(&payload_raw_bytes, needle).unwrap() + needle.len();
        let from_len = find_subsequence(&payload_raw_bytes[from_left_index..], br#"""#).unwrap();

        println!(
            "id: [{}]",
            String::from_utf8_lossy(
                &payload_raw_bytes[from_left_index..from_left_index + from_len]
            )
        );
        let mut email_addr_pepper_bytes =
            payload_raw_bytes[from_left_index..from_left_index + from_len].to_vec();
        let pepper = [0u8; 32];
        email_addr_pepper_bytes.extend(pepper);

        let mut payload_pub_match = payload_raw_bytes.clone();
        for i in from_left_index..from_left_index + from_len {
            payload_pub_match[i] = 0;
        }

        let circuit = OpenIdCircuit {
            id_token_bytes: id_token.as_bytes().to_vec(),
            header_raw_bytes,
            payload_raw_bytes,
            payload_pub_match,
            email_addr_pepper_bytes,

            header_base64_len,
            payload_left_index,
            payload_base64_len,
            from_left_index: from_left_index as u32,
            from_len: from_len as u32,
        };

        let mut cs = circuit.synthesize();
        test_prove_verify(&mut cs).unwrap();
    }
}
