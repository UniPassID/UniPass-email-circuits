use base64::Engine;
use plonk::{
    ark_bn254::Fr,
    ark_std::{One, Zero},
    sha256::{
        sha256_collect_8_outputs_to_field, sha256_no_padding_words_var_fixed_length, Sha256Word,
    },
    Composer,
};

use super::{
    base64::{base64url_decode_gadget, enforce_encoded_len},
    misc::{enforce_eq_before_index, public_match_before_index, sha256_var},
};

pub const PAYLOAD_RAW_MAX_LEN: usize = 1152;
// (PAYLOAD_RAW_MAX_LEN / 3) * 4
pub const PAYLOAD_BASE64_MAX_LEN: usize = 1536;

pub const HEADER_RAW_MAX_LEN: usize = 384;
pub const HEADER_BASE64_MAX_LEN: usize = 512;

pub const ID_TOKEN_MAX_LEN: usize = 2048;
pub const SUB_MAX_LEN: usize = 192;

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub struct OpenIdCircuit {
    pub id_token_bytes: Vec<u8>,
    pub header_base64_bytes: Vec<u8>,
    pub payload_base64_bytes: Vec<u8>,
    pub header_raw_bytes: Vec<u8>,
    pub payload_raw_bytes: Vec<u8>,

    pub sub_pepper_bytes: Vec<u8>,
    pub payload_pub_match: Vec<u8>,

    pub header_left_index: u32,
    pub header_base64_len: u32,
    pub header_raw_len: u32,
    pub payload_left_index: u32,
    pub payload_base64_len: u32,
    pub payload_raw_len: u32,
    pub sub_left_index: u32,
    pub sub_len: u32,
}

impl OpenIdCircuit {
    pub fn new(id_token: &str, from_pepper: &[u8]) -> Self {
        let id_tokens: Vec<_> = id_token.split('.').collect();
        let header_base64_bytes = id_tokens[0].as_bytes().to_vec();
        let payload_base64_bytes = id_tokens[1].as_bytes().to_vec();
        let raw_id_tokens = String::from(id_tokens[0]) + "." + id_tokens[1];

        let payload_left_index = (header_base64_bytes.len() + 1) as u32;
        let payload_base64_len = payload_base64_bytes.len() as u32;
        let header_base64_len = header_base64_bytes.len() as u32;

        let base64url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload_raw_bytes = base64url_engine.decode(&payload_base64_bytes).unwrap();
        let header_raw_bytes = base64url_engine.decode(&header_base64_bytes).unwrap();

        let payload_raw_len = payload_raw_bytes.len() as u32;
        let header_raw_len = header_raw_bytes.len() as u32;

        let needle = br#""sub":""#;
        let sub_left_index = find_subsequence(&payload_raw_bytes, needle).unwrap() + needle.len();
        let sub_len = find_subsequence(&payload_raw_bytes[sub_left_index..], br#"""#).unwrap();

        let mut sub_pepper_bytes =
            payload_raw_bytes[sub_left_index..sub_left_index + sub_len].to_vec();

        sub_pepper_bytes.extend(from_pepper);

        let mut payload_pub_match = payload_raw_bytes.clone();
        for i in sub_left_index..sub_left_index + sub_len {
            payload_pub_match[i] = 0;
        }

        OpenIdCircuit {
            id_token_bytes: raw_id_tokens.as_bytes().to_vec(),
            header_base64_bytes,
            payload_base64_bytes,
            header_raw_bytes,
            payload_raw_bytes,
            payload_pub_match,
            sub_pepper_bytes,

            header_left_index: 0,
            header_base64_len,
            header_raw_len,
            payload_left_index,
            payload_base64_len,
            payload_raw_len,
            sub_left_index: sub_left_index as u32,
            sub_len: sub_len as u32,
        }
    }

    pub fn synthesize(&self) -> Composer<Fr> {
        let mut cs = Composer::new(5, false);

        // get the id_token hash
        let (id_token_padding_vars, id_token_hash) =
            sha256_var(&mut cs, &self.id_token_bytes, ID_TOKEN_MAX_LEN).unwrap();
        // get the sub_pepper hash
        let (sub_pepper_vars, sub_pepper_hash) =
            sha256_var(&mut cs, &self.sub_pepper_bytes, SUB_MAX_LEN).unwrap();

        // construct header_pub_match and calculate hash
        let (payload_pub_match_vars, payload_pub_match_hash) =
            sha256_var(&mut cs, &self.payload_pub_match, PAYLOAD_RAW_MAX_LEN).unwrap();

        // calculate header_raw hash
        let (header_raw_vars, header_hash) =
            sha256_var(&mut cs, &self.header_raw_bytes, HEADER_RAW_MAX_LEN).unwrap();

        let mut header_base64_vars = vec![];
        for e in &self.header_base64_bytes {
            header_base64_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = header_base64_vars.len();
        for _ in n..HEADER_BASE64_MAX_LEN {
            header_base64_vars.push(cs.alloc(Fr::zero()));
        }

        // calculate header base64 decode
        let header_decoded_vars =
            base64url_decode_gadget(&mut cs, &header_base64_vars, HEADER_BASE64_MAX_LEN).unwrap();

        // start index of the encoded header
        let header_left_index = cs.alloc(Fr::from(self.header_left_index));
        // length of the encoded header
        let header_base64_len = cs.alloc(Fr::from(self.header_base64_len));

        let header_raw_len = cs.alloc(Fr::from(self.header_raw_len));

        enforce_encoded_len(&mut cs, header_raw_len, header_base64_len).unwrap();

        enforce_eq_before_index(
            &mut cs,
            HEADER_RAW_MAX_LEN,
            header_raw_len,
            &header_raw_vars,
            &header_decoded_vars,
        );

        // calculate payload base64 encode
        let mut payload_base64_vars = vec![];
        for e in &self.payload_base64_bytes {
            payload_base64_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = payload_base64_vars.len();
        for _ in n..PAYLOAD_BASE64_MAX_LEN {
            payload_base64_vars.push(cs.alloc(Fr::zero()));
        }

        let payload_decoded_vars =
            base64url_decode_gadget(&mut cs, &payload_base64_vars, PAYLOAD_BASE64_MAX_LEN).unwrap();

        // start index of the encoded payload
        let payload_left_index = cs.alloc(Fr::from(self.payload_left_index));
        // length of the encoded payload
        let payload_base64_len = cs.alloc(Fr::from(self.payload_base64_len));

        let payload_raw_len = cs.alloc(Fr::from(self.payload_raw_len));

        enforce_encoded_len(&mut cs, payload_raw_len, payload_base64_len).unwrap();

        // pub match "a"
        // public string match.
        public_match_before_index(
            &mut cs,
            PAYLOAD_RAW_MAX_LEN,
            payload_raw_len,
            &payload_decoded_vars,
            &payload_pub_match_vars,
        );

        let (bit_location_id_token_1, bit_location_payload_base64) = cs
            .gen_bit_location_for_substr(
                payload_left_index,
                payload_base64_len,
                ID_TOKEN_MAX_LEN,
                PAYLOAD_BASE64_MAX_LEN,
            )
            .unwrap();
        {
            let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &id_token_hash).unwrap();
            // private substring check.
            cs.add_substring_mask_poly_return_words(
                &id_token_padding_vars,
                &payload_base64_vars,
                &bit_location_id_token_1,
                &bit_location_payload_base64,
                mask_r,
                payload_left_index,
                payload_base64_len,
                ID_TOKEN_MAX_LEN,
                PAYLOAD_BASE64_MAX_LEN,
            )
            .unwrap();
        }

        let (bit_location_id_token_2, bit_location_header_base64) = cs
            .gen_bit_location_for_substr(
                header_left_index,
                header_base64_len,
                ID_TOKEN_MAX_LEN,
                HEADER_BASE64_MAX_LEN,
            )
            .unwrap();
        {
            let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &header_hash).unwrap();
            // private substring check.
            cs.add_substring_mask_poly_return_words(
                &id_token_padding_vars,
                &header_base64_vars,
                &bit_location_id_token_2,
                &bit_location_header_base64,
                mask_r,
                header_left_index,
                header_base64_len,
                ID_TOKEN_MAX_LEN,
                HEADER_BASE64_MAX_LEN,
            )
            .unwrap();
        }

        // start index of the sub address
        let sub_left_index = cs.alloc(Fr::from(self.sub_left_index));
        // length of the sub address
        let sub_len = cs.alloc(Fr::from(self.sub_len));

        let (bit_location_payload_raw, bit_location_sub) = cs
            .gen_bit_location_for_substr(sub_left_index, sub_len, PAYLOAD_RAW_MAX_LEN, SUB_MAX_LEN)
            .unwrap();
        {
            let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &sub_pepper_hash).unwrap();
            // private substring check.
            cs.add_substring_mask_poly_return_words(
                &payload_decoded_vars,
                &sub_pepper_vars,
                &bit_location_payload_raw,
                &bit_location_sub,
                mask_r,
                sub_left_index,
                sub_len,
                PAYLOAD_RAW_MAX_LEN,
                SUB_MAX_LEN,
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
        let output_words_sub = cs
            .collect_bit_location_for_sha256(SUB_MAX_LEN, &bit_location_sub)
            .unwrap();

        // 8544 bit, id_token_hash(256)|sub_hash(256)|header_hash(256)|payload_pubmatch_hash(256)
        // |bit_location_id_token_1(2048)|bit_location_payload_base64(1536)|bit_location_id_token_2(2048)|bit_location_header_base64(512)
        // |bit_location_payload_raw(1152)|bit_location_sub(192)|header_base64_len(16)|payload_base64_len(16)
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
        for wd in sub_pepper_hash {
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
        for wd in output_words_sub {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        // (header_base64_len|payload_base64_len) as a 32bits word
        let word_var = {
            let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
            assert!(spread16_index != 0);
            let _ = cs
                .read_from_table(
                    spread16_index,
                    vec![header_base64_len, Composer::<Fr>::null()],
                )
                .unwrap();
            let _ = cs
                .read_from_table(
                    spread16_index,
                    vec![payload_base64_len, Composer::<Fr>::null()],
                )
                .unwrap();

            let word_var = cs.alloc(
                Fr::from(self.header_base64_len as u64) * Fr::from(1u64 << 16)
                    + Fr::from(self.payload_base64_len as u64),
            );

            cs.poly_gate(
                vec![
                    (word_var, -Fr::one()),
                    (header_base64_len, Fr::from(1u64 << 16)),
                    (payload_base64_len, Fr::one()),
                ],
                Fr::zero(),
                Fr::zero(),
            );

            word_var
        };
        let word = Sha256Word {
            var: word_var,
            hvar: Composer::<Fr>::null(),
            lvar: Composer::<Fr>::null(),
            hvar_spread: Composer::<Fr>::null(),
            lvar_spread: Composer::<Fr>::null(),
        };
        sha256_all_public_data.push(word);

        // padding (96bits + 64bits)
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
            for _ in 0..3 {
                let word = Sha256Word {
                    var: Composer::<Fr>::null(),
                    hvar: Composer::<Fr>::null(),
                    lvar: Composer::<Fr>::null(),
                    hvar_spread: Composer::<Fr>::null(),
                    lvar_spread: Composer::<Fr>::null(),
                };
                sha256_all_public_data.push(word);
            }
            let pad_value = Fr::from(8544u64);
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

        cs
    }
}
