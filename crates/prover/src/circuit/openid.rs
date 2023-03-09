use base64::Engine;
use plonk::{
    ark_bn254::Fr,
    ark_std::{One, Zero},
    sha256::{
        sha256_collect_8_outputs_to_field, sha256_no_padding_words_var,
        sha256_no_padding_words_var_fixed_length, Sha256Word,
    },
    Composer, Field,
};

use crate::utils::padding_bytes;

use super::base64::base64url_encode_gadget;

pub const PAYLOAD_RAW_MAX_LEN: usize = 1152;
// (PAYLOAD_RAW_MAX_LEN / 3) * 4
pub const PAYLOAD_BASE64_MAX_LEN: usize = 1536;

pub const HEADER_RAW_MAX_LEN: usize = 384;
pub const HEADER_BASE64_MAX_LEN: usize = 512;

pub const ID_TOKEN_MAX_LEN: usize = 2048;
pub const EMAIL_ADDR_MAX_LEN: usize = 192;

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

    pub header_left_index: u32,
    pub header_base64_len: u32,
    pub payload_left_index: u32,
    pub payload_base64_len: u32,
    pub addr_left_index: u32,
    pub addr_len: u32,
}

impl OpenIdCircuit {
    pub fn new(id_token: &str, from_pepper: &[u8]) -> Self {
        let id_tokens: Vec<_> = id_token.split('.').collect();
        let header_base64_bytes = id_tokens[0].as_bytes().to_vec();
        let payload_base64_bytes = id_tokens[1].as_bytes().to_vec();

        let payload_left_index = (header_base64_bytes.len() + 1) as u32;
        let payload_base64_len = payload_base64_bytes.len() as u32;
        let header_base64_len = header_base64_bytes.len() as u32;

        let base64url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload_raw_bytes = base64url_engine.decode(&payload_base64_bytes).unwrap();
        let header_raw_bytes = base64url_engine.decode(&header_base64_bytes).unwrap();

        let needle = br#""email":""#;
        let addr_left_index = find_subsequence(&payload_raw_bytes, needle).unwrap() + needle.len();
        let addr_len = find_subsequence(&payload_raw_bytes[addr_left_index..], br#"""#).unwrap();

        let mut email_addr_pepper_bytes =
            payload_raw_bytes[addr_left_index..addr_left_index + addr_len].to_vec();

        email_addr_pepper_bytes.extend(from_pepper);

        let mut payload_pub_match = payload_raw_bytes.clone();
        for i in addr_left_index..addr_left_index + addr_len {
            payload_pub_match[i] = 0;
        }

        OpenIdCircuit {
            id_token_bytes: id_token.as_bytes().to_vec(),
            header_raw_bytes,
            payload_raw_bytes,
            payload_pub_match,
            email_addr_pepper_bytes,

            header_left_index: 0,
            header_base64_len,
            payload_left_index,
            payload_base64_len,
            addr_left_index: addr_left_index as u32,
            addr_len: addr_len as u32,
        }
    }
    pub fn synthesize(&self) -> Composer<Fr> {
        let mut cs = Composer::new(5, false);

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
        let email_addr_padding_len = (email_addr_pepper_bytes_padding.len() / 64) as u32;
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
        let email_addr_pepper_data_len = cs.alloc(Fr::from(email_addr_padding_len));

        // cal sha256 of email_pepper
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

        {
            let a = cs.get_assignments(&payload_encoded_vars);
            let output_str: Vec<_> = a
                .into_iter()
                .map(|a| a.into_repr().as_ref()[0] as u8)
                .collect();
            println!("payload_encoded: {}", String::from_utf8_lossy(&output_str));
        }
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
        for e in &header_raw_bytes_padding {
            header_raw_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = header_raw_vars.len();
        for _ in n..HEADER_RAW_MAX_LEN {
            header_raw_vars.push(cs.alloc(Fr::zero()));
        }

        {
            let a = cs.get_assignments(&header_raw_vars);
            let output_str: Vec<_> = a
                .into_iter()
                .map(|a| a.into_repr().as_ref()[0] as u8)
                .collect();
            println!("header_raw: {}", String::from_utf8_lossy(&output_str));
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
        {
            let a = cs.get_assignments(&header_encoded_vars);
            let output_str: Vec<_> = a
                .into_iter()
                .map(|a| a.into_repr().as_ref()[0] as u8)
                .collect();
            println!("header_encoded: {}", String::from_utf8_lossy(&output_str));
        }
        // start index of the encoded payload
        let payload_left_index = cs.alloc(Fr::from(self.payload_left_index));
        // length of the encoded payload
        let payload_base64_len = cs.alloc(Fr::from(self.payload_base64_len));
        let payload_base64_len_minus_1 = cs.alloc(Fr::from(self.payload_base64_len - 1));
        cs.poly_gate(
            vec![
                (payload_base64_len, Fr::one()),
                (payload_base64_len_minus_1, -Fr::one()),
            ],
            Fr::zero(),
            -Fr::one(),
        );
        let (bit_location_id_token_1, bit_location_payload_base64) = cs
            .gen_bit_location_for_substr(
                payload_left_index,
                payload_base64_len_minus_1,
                ID_TOKEN_MAX_LEN,
                PAYLOAD_BASE64_MAX_LEN,
            )
            .unwrap();
        {
            let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &id_token_hash).unwrap();
            // private substring check.
            cs.add_substring_mask_poly_return_words(
                &id_token_padding_vars,
                &payload_encoded_vars,
                &bit_location_id_token_1,
                &bit_location_payload_base64,
                mask_r,
                payload_left_index,
                payload_base64_len_minus_1,
                ID_TOKEN_MAX_LEN,
                PAYLOAD_BASE64_MAX_LEN,
            )
            .unwrap();
        }

        // start index of the encoded header
        let header_left_index = cs.alloc(Fr::from(self.header_left_index));
        // length of the encoded header
        let header_base64_len = cs.alloc(Fr::from(self.header_base64_len));
        let header_base64_len_minus_1 = cs.alloc(Fr::from(self.header_base64_len - 1));
        cs.poly_gate(
            vec![
                (header_base64_len, Fr::one()),
                (header_base64_len_minus_1, -Fr::one()),
            ],
            Fr::zero(),
            -Fr::one(),
        );
        let (bit_location_id_token_2, bit_location_header_base64) = cs
            .gen_bit_location_for_substr(
                header_left_index,
                header_base64_len_minus_1,
                ID_TOKEN_MAX_LEN,
                HEADER_BASE64_MAX_LEN,
            )
            .unwrap();
        {
            let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &header_hash).unwrap();
            // private substring check.
            cs.add_substring_mask_poly_return_words(
                &id_token_padding_vars,
                &header_encoded_vars,
                &bit_location_id_token_2,
                &bit_location_header_base64,
                mask_r,
                header_left_index,
                header_base64_len_minus_1,
                ID_TOKEN_MAX_LEN,
                HEADER_BASE64_MAX_LEN,
            )
            .unwrap();
        }
        // start index of the email address
        let addr_left_index = cs.alloc(Fr::from(self.addr_left_index));
        // length of the email address
        let addr_len = cs.alloc(Fr::from(self.addr_len));

        let (bit_location_payload_raw, bit_location_email_addr) = cs
            .gen_bit_location_for_substr(
                addr_left_index,
                addr_len,
                PAYLOAD_RAW_MAX_LEN,
                EMAIL_ADDR_MAX_LEN,
            )
            .unwrap();
        {
            let mask_r =
                sha256_collect_8_outputs_to_field(&mut cs, &email_addr_pepper_hash).unwrap();
            // private substring check.
            cs.add_substring_mask_poly_return_words(
                &payload_raw_vars,
                &email_addr_pepper_vars,
                &bit_location_payload_raw,
                &bit_location_email_addr,
                mask_r,
                addr_left_index,
                addr_len,
                PAYLOAD_RAW_MAX_LEN,
                EMAIL_ADDR_MAX_LEN,
            )
            .unwrap();
        }
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
        // bit_location_id_token_2|bit_location_header_base64|bit_location_payload_raw|bit_location_email_addr|
        // id_token_len|header_raw_len|payload_raw_len|email_addr_pepper_len
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

        cs
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::{
        circuit::openid::{
            EMAIL_ADDR_MAX_LEN, HEADER_BASE64_MAX_LEN, ID_TOKEN_MAX_LEN, PAYLOAD_BASE64_MAX_LEN,
            PAYLOAD_RAW_MAX_LEN,
        },
        utils::{bit_location, convert_public_inputs, to_0x_hex},
    };

    use super::OpenIdCircuit;
    use plonk::{
        ark_bn254::{self, Fr},
        ark_std::test_rng,
        kzg10::PCKey,
        prover,
        verifier::Verifier,
        Composer, Error, Field, GeneralEvaluationDomain,
    };
    use sha2::Digest;

    fn test_prove_verify(
        cs: &mut Composer<Fr>,
        expected_public_input: Vec<Fr>,
    ) -> Result<(), Error> {
        println!();
        let public_input = cs.compute_public_input();
        println!(
            "[main] public input: {:?}, expected: {:?}",
            convert_public_inputs(&public_input),
            convert_public_inputs(&expected_public_input),
        );
        if expected_public_input != public_input {
            panic!("public input error")
        }

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
        let id_tokens = ["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImgzejJzZnFQcU1WQmNKQUJKM1FRQSJ9.eyJuaWNrbmFtZSI6IjEzMjExMTQ2IiwibmFtZSI6IuWNkyDpg5EiLCJwaWN0dXJlIjoiaHR0cHM6Ly9zLmdyYXZhdGFyLmNvbS9hdmF0YXIvZGQ1YjJjM2NjNjU2ZTgzYWYxOTE5NmI4YzA1OGZkYTg_cz00ODAmcj1wZyZkPWh0dHBzJTNBJTJGJTJGY2RuLmF1dGgwLmNvbSUyRmF2YXRhcnMlMkZkZWZhdWx0LnBuZyIsInVwZGF0ZWRfYXQiOiIyMDIzLTAzLTAzVDA4OjQyOjQxLjc5M1oiLCJlbWFpbCI6IjEzMjExMTQ2QGJqdHUuZWR1LmNuIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLndhbGxldC51bmlwYXNzLmlkLyIsImF1ZCI6InZyNktJZ2h4Q3FtRWxwQWQ0VE5EMG5yTUJpQVIzWDJtIiwiaWF0IjoxNjc3ODMyOTYyLCJleHAiOjE2Nzc4MzY1NjIsInN1YiI6ImFwcGxlfDAwMDA2MS4xZTkzNmMwNmUzNWE0OWI5YmJmYzBmMzJjY2FlNTMyZC4xNDMzIiwiYXV0aF90aW1lIjoxNjc3ODMyOTYxLCJhdF9oYXNoIjoiVmpLekRsMEU1SlhyZDRxYkItQm9LZyIsInNpZCI6InBSYWxnWkMwUlhtTng3SjlCRzEtSjBWbGQtbXd4QmpHIiwibm9uY2UiOiJHRllRWE1RVEpoSnRiUWlxdHNsaHR2SEZ1WDRyYzdVZyJ9",
        "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1NWNjYTZlYzI4MTA2MDJkODBiZWM4OWU0NTZjNDQ5NWQ3NDE4YmIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDc2MjQ5Njg2NjQyLWcwZDQyNTI0ZmhkaXJqZWhvMHQ2bjNjamQ3cHVsbW5zLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTA3NjI0OTY4NjY0Mi1nMGQ0MjUyNGZoZGlyamVobzB0Nm4zY2pkN3B1bG1ucy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNDMzMTY2MDQxMDE2NDA1MzAyMSIsImhkIjoibGF5Mi5kZXYiLCJlbWFpbCI6Inp6aGVuQGxheTIuZGV2IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJqNmQ1aHRFLTF0Mm1Pd2ZQRUFTMXpRIiwibm9uY2UiOiIyYWVjNzM4MSIsImlhdCI6MTY3ODE4OTg4NCwiZXhwIjoxNjc4MTkzNDg0LCJqdGkiOiJkMTRkNTcxYTlhNmRmZmZjNmU2OTM2NjBiNDhlODdlYjIyNTMyYjg5In0"];
        for id_token in id_tokens {
            let from_pepper = [0u8; 32];
            let circuit = OpenIdCircuit::new(id_token, &from_pepper);

            let header_hash = sha2::Sha256::digest(&circuit.header_raw_bytes).to_vec();
            println!("header hash: {}", to_0x_hex(&header_hash));

            let idtoken_hash = sha2::Sha256::digest(id_token).to_vec();
            let payload_pub_match_hash = sha2::Sha256::digest(&circuit.payload_pub_match).to_vec();
            let email_addr_peper_hash =
                sha2::Sha256::digest(&circuit.email_addr_pepper_bytes).to_vec();

            let mut hash_inputs = vec![];
            hash_inputs.extend(idtoken_hash);
            hash_inputs.extend(email_addr_peper_hash);
            hash_inputs.extend(header_hash);
            hash_inputs.extend(payload_pub_match_hash);

            let (location_id_token_1, location_payload_base64) = bit_location(
                circuit.payload_left_index,
                circuit.payload_base64_len - 1,
                ID_TOKEN_MAX_LEN as u32,
                PAYLOAD_BASE64_MAX_LEN as u32,
            );
            let (location_id_token_2, location_header_base64) = bit_location(
                0,
                circuit.header_base64_len - 1,
                ID_TOKEN_MAX_LEN as u32,
                HEADER_BASE64_MAX_LEN as u32,
            );
            let (location_payload_raw, location_email_addr) = bit_location(
                circuit.addr_left_index as u32,
                circuit.addr_len as u32,
                PAYLOAD_RAW_MAX_LEN as u32,
                EMAIL_ADDR_MAX_LEN as u32,
            );

            hash_inputs.extend(location_id_token_1);
            hash_inputs.extend(location_payload_base64);
            hash_inputs.extend(location_id_token_2);
            hash_inputs.extend(location_header_base64);
            hash_inputs.extend(location_payload_raw);
            hash_inputs.extend(location_email_addr);

            let mut public_input = sha2::Sha256::digest(&hash_inputs).to_vec();
            public_input[0] = public_input[0] & 0x1f;

            println!("public_input: {}", to_0x_hex(&public_input));

            let mut cs = circuit.synthesize();
            test_prove_verify(&mut cs, vec![Fr::from_be_bytes_mod_order(&public_input)]).unwrap();
        }
    }
}
