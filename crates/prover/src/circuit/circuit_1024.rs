use plonk::ark_bn254::Fr;
use plonk::ark_ff::{One, Zero};

use email_parser::types::PrivateInputs;
use plonk::sha256::sha256_no_padding_words_var_fixed_length;
use plonk::{
    sha256::{sha256_collect_8_outputs_to_field, sha256_no_padding_words_var, Sha256Word},
    Composer,
};

use crate::{error::ProverError, utils::padding_bytes};

pub struct Email1024CircuitInput {
    pub email_header_bytes: Vec<u8>,
    pub email_addr_pepper_bytes: Vec<u8>,
    pub email_header_pub_match: Vec<u8>,
    pub from_left_index: u32,
    pub from_len: u32,
}

impl Email1024CircuitInput {
    pub fn parameters() -> (usize, usize) {
        (1024, 192)
    }

    pub fn new(mut private_inputs: PrivateInputs) -> Result<Self, ProverError> {
        let email_addr_bytes = private_inputs.email_header
            [private_inputs.from_left_index..private_inputs.from_right_index + 1]
            .to_vec();
        let mut email_addr_pepper_bytes = email_addr_bytes.clone();
        email_addr_pepper_bytes.append(&mut private_inputs.from_pepper);

        let email_header_bytes = private_inputs.email_header.clone();

        // set any byte of "pub match string" to "0" is OK.
        // (you can only remain bytes for format checking, set all other bytes to 0)
        let mut email_header_pub_match = email_header_bytes.clone();

        for i in 0..email_header_pub_match.len() {
            if private_inputs.from_index == 0 {
                if i >= private_inputs.from_index && i < private_inputs.from_left_index {
                    continue;
                }
            } else {
                if i >= private_inputs.from_index - 2 && i < private_inputs.from_left_index {
                    continue;
                }
            }

            if i == private_inputs.from_right_index + 1 {
                continue;
            }

            if private_inputs.subject_index == 0 {
                if i >= private_inputs.subject_index && i < private_inputs.subject_right_index {
                    continue;
                }
            } else {
                if i >= private_inputs.subject_index - 2 && i < private_inputs.subject_right_index {
                    continue;
                }
            }

            if i == private_inputs.dkim_header_index - 2 {
                break;
            }

            email_header_pub_match[i] = 0;
        }

        let from_len =
            (private_inputs.from_right_index - private_inputs.from_left_index + 1) as u32;
        let from_left_index = private_inputs.from_left_index as u32;

        Ok(Self {
            email_header_bytes,
            email_addr_pepper_bytes,
            email_header_pub_match,
            from_left_index,
            from_len,
        })
    }

    pub fn synthesize(&self) -> Composer<Fr> {
        // new '5 column' circuit
        let mut cs = Composer::new(5, false);
        let (email_header_max_lens, email_addr_max_lens) = Self::parameters();

        // padding bytes
        let email_header_bytes_padding = padding_bytes(&self.email_header_bytes);
        let email_addr_pepper_bytes_padding = padding_bytes(&self.email_addr_pepper_bytes);
        let email_header_pub_match_padding = padding_bytes(&self.email_header_pub_match);
        let from_padding_len = (email_addr_pepper_bytes_padding.len() / 64) as u32;
        let header_padding_len = (email_header_bytes_padding.len() / 64) as u32;

        // alloc variables for "a"
        let mut email_header_vars = vec![];
        for e in &email_header_bytes_padding {
            email_header_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = email_header_vars.len();
        // padding "a" to max_lens
        for _ in n..email_header_max_lens {
            email_header_vars.push(cs.alloc(Fr::zero()));
        }

        // alloc variables for "b"
        let mut email_addr_pepper_vars = vec![];
        for e in &email_addr_pepper_bytes_padding {
            email_addr_pepper_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = email_addr_pepper_vars.len();
        // padding "b" to b_max_lens
        for _ in n..email_addr_max_lens {
            email_addr_pepper_vars.push(cs.alloc(Fr::zero()));
        }

        // start index of the email address
        let l = cs.alloc(Fr::from(self.from_left_index));
        // length of the email address
        let m = cs.alloc(Fr::from(self.from_len));

        // "sample_a_bytes_padding" is 8*512 bits, so we need the index to output correct sha256
        let email_header_data_len = cs.alloc(Fr::from(header_padding_len));
        // "sample_b_bytes_padding" is 2*512 bits, so we need the index to output correct sha256
        let email_addr_pepper_data_len = cs.alloc(Fr::from(from_padding_len));
        // 2 values above should be public, we will handle that later in the hash.

        // cal sha256 of "a"
        let mut sha256_a_data = vec![];
        for vs in email_header_vars.chunks(4) {
            // "Sha256Word" is the type we need in the sha256, each contain 32bits
            sha256_a_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }
        // get the hash
        let email_header_hash = sha256_no_padding_words_var(
            &mut cs,
            &sha256_a_data,
            email_header_data_len,
            email_header_max_lens * 8 / 512,
        )
        .unwrap();

        // cal sha256 of b_pepper
        let mut sha256_b_data = vec![];
        for vs in email_addr_pepper_vars.chunks(4) {
            sha256_b_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }
        let email_addr_pepper_hash = sha256_no_padding_words_var(
            &mut cs,
            &sha256_b_data,
            email_addr_pepper_data_len,
            email_addr_max_lens * 8 / 512,
        )
        .unwrap();

        // cal sha256(a_hash|b_hash)
        let mut concat_hash = email_header_hash.clone();
        let mut tmp_email_addr_pepper_hash = email_addr_pepper_hash.clone();
        concat_hash.append(&mut tmp_email_addr_pepper_hash);
        // padding
        {
            let pad_value = Fr::from(1u64 << 31);
            let tmp_var = cs.alloc(pad_value);
            cs.enforce_constant(tmp_var, pad_value);
            concat_hash.push(tmp_var);
            for _ in 0..14 {
                concat_hash.push(Composer::<Fr>::null());
            }
            let pad_value = Fr::from(512);
            let tmp_var = cs.alloc(pad_value);
            cs.enforce_constant(tmp_var, pad_value);
            concat_hash.push(tmp_var);
        }
        let mut concat_hash_data = vec![];
        for v in concat_hash {
            let word = Sha256Word {
                var: v,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            concat_hash_data.push(word);
        }
        let mask_hashs =
            sha256_no_padding_words_var_fixed_length(&mut cs, &concat_hash_data, 2).unwrap();

        let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &mask_hashs).unwrap();

        // private substring check. use sha256(a_hash|b_hash) as mask_r
        let (output_words_a, output_words_b) = cs
            .add_substring_mask_poly_return_words(
                &email_header_vars,
                &email_addr_pepper_vars,
                mask_r,
                l,
                m,
                email_header_max_lens,
                email_addr_max_lens,
            )
            .unwrap();

        // pub match "a"
        // public string to be matched
        let mut email_header_pubmatch_vars = vec![];
        for e in &email_header_pub_match_padding {
            email_header_pubmatch_vars.push(cs.alloc(Fr::from(*e)));
        }
        // padding to max_lens
        let n = email_header_pubmatch_vars.len();
        for _ in n..email_header_max_lens {
            email_header_pubmatch_vars.push(cs.alloc(Fr::zero()));
        }

        // public string match.
        cs.add_public_match_no_custom_gate(
            &email_header_vars,
            &email_header_pubmatch_vars,
            email_header_max_lens,
        );

        // gen pub_inputs
        // hash all public. 9952bits (256|256|1024|192|1024*8|16|16)
        // cal sha256(a_hash|b_hash|a_bits_location|b_bits_location|pub_string|header_len|addr_len)
        let mut sha256_all_public_data = vec![];
        for wd in email_header_hash {
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
        for wd in output_words_a {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for wd in output_words_b {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }
        for vs in email_header_pubmatch_vars.chunks(4) {
            sha256_all_public_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }
        // (header_len|addr_len) as a 32bits word
        let word_var = {
            let spread8_index = cs.get_table_index(format!("spread_8bits"));
            assert!(spread8_index != 0);
            let _ = cs
                .read_from_table(spread8_index, vec![email_header_data_len])
                .unwrap();
            let _ = cs
                .read_from_table(spread8_index, vec![email_addr_pepper_data_len])
                .unwrap();

            let word_var = cs.alloc(
                Fr::from(header_padding_len as u64) * Fr::from(1u64 << 16)
                    + Fr::from(from_padding_len as u64),
            );

            cs.poly_gate(
                vec![
                    (word_var, -Fr::one()),
                    (email_header_data_len, Fr::from(1u64 << 16)),
                    (email_addr_pepper_data_len, Fr::one()),
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
        // padding (224bits + 64bits)
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
            for _ in 0..7 {
                let word = Sha256Word {
                    var: Composer::<Fr>::null(),
                    hvar: Composer::<Fr>::null(),
                    lvar: Composer::<Fr>::null(),
                    hvar_spread: Composer::<Fr>::null(),
                    lvar_spread: Composer::<Fr>::null(),
                };
                sha256_all_public_data.push(word);
            }
            let pad_value = Fr::from(19168u64);
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
            sha256_no_padding_words_var_fixed_length(&mut cs, &sha256_all_public_data, 20).unwrap();

        let public_inputs_hash =
            sha256_collect_8_outputs_to_field(&mut cs, &all_public_hash).unwrap();

        cs.set_variable_public_input(public_inputs_hash);

        cs
    }
}
