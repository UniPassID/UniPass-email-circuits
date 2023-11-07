use plonk::ark_bn254::Fr;
use plonk::ark_ff::{One, Zero};

use email_parser::types::PrivateInputs;
use plonk::sha256::sha256_no_padding_words_var_fixed_length;
use plonk::{
    sha256::{sha256_collect_8_outputs_to_field, Sha256Word},
    Composer,
};

use crate::error::ProverError;

use super::misc::{sha256_var, sub_slice_check};

pub struct Email1024CircuitInput {
    pub email_header_bytes: Vec<u8>,
    pub email_addr_pepper_bytes: Vec<u8>,
    pub email_header_pub_match: Vec<u8>,
    pub from_left_index: u32,
    pub from_len: u32,
}

impl Email1024CircuitInput {
    pub fn parameters() -> (usize, usize) {
        (1088, 192)
    }

    pub fn new(mut private_inputs: PrivateInputs) -> Result<Self, ProverError> {
        if private_inputs.from_index >= private_inputs.from_left_index
            || private_inputs.from_left_index >= private_inputs.from_right_index
        {
            return Err(ProverError::SpecificError(
                "private_inputs format error".to_owned(),
            ));
        }
        if private_inputs.subject_index > private_inputs.subject_right_index {
            return Err(ProverError::SpecificError(
                "private_inputs format error".to_owned(),
            ));
        }

        let email_addr_bytes = private_inputs.email_header
            [private_inputs.from_left_index..private_inputs.from_right_index + 1]
            .to_vec();
        let mut email_addr_pepper_bytes = email_addr_bytes;
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
            } else if i >= private_inputs.from_index - 2 && i < private_inputs.from_left_index {
                continue;
            }

            if i == private_inputs.from_right_index + 1 {
                continue;
            }

            if private_inputs.subject_index == 0 {
                if i >= private_inputs.subject_index && i < private_inputs.subject_right_index {
                    continue;
                }
            } else if i >= private_inputs.subject_index - 2
                && i < private_inputs.subject_right_index
            {
                continue;
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

        // calculate email_header_hash
        let (email_header_vars, email_header_hash) =
            sha256_var(&mut cs, &self.email_header_bytes, email_header_max_lens).unwrap();

        // calculate email_addr_pepper_hash
        let (email_addr_pepper_vars, email_addr_pepper_hash) =
            sha256_var(&mut cs, &self.email_addr_pepper_bytes, email_addr_max_lens).unwrap();

        // calculate pubmatch_hash
        let (email_header_pubmatch_vars, pubmatch_hash) =
            sha256_var(&mut cs, &self.email_header_pub_match, email_header_max_lens).unwrap();

        // start index of the email address
        let from_left_index = cs.alloc(Fr::from(self.from_left_index));
        // length of the email address
        let from_len = cs.alloc(Fr::from(self.from_len));

        // private substring check.
        // email_addr is a substring of email_header
        sub_slice_check(
            &mut cs,
            email_header_max_lens,
            email_addr_max_lens,
            &email_header_vars,
            &email_addr_pepper_vars,
            from_left_index,
            from_len,
        );

        // pub match "email_header"
        // public string match.
        cs.add_public_match_no_custom_gate(
            &email_header_vars,
            &email_header_pubmatch_vars,
            email_header_max_lens,
        );

        // cal 800bits sha256(header_hash|addr_hash|header_pub_hash|from_left_index|from_len)
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
        for wd in pubmatch_hash {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
        }

        // (from_index|from_len) as a 32bits word
        let word_var = {
            let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
            assert!(spread16_index != 0);
            let _ = cs
                .read_from_table(
                    spread16_index,
                    vec![from_left_index, Composer::<Fr>::null()],
                )
                .unwrap();
            let _ = cs
                .read_from_table(spread16_index, vec![from_len, Composer::<Fr>::null()])
                .unwrap();

            let word_var = cs.alloc(
                Fr::from(self.from_left_index as u64) * Fr::from(1u64 << 16)
                    + Fr::from(self.from_len as u64),
            );

            cs.poly_gate(
                vec![
                    (word_var, -Fr::one()),
                    (from_left_index, Fr::from(1u64 << 16)),
                    (from_len, Fr::one()),
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
        // padding (160its + 64bits)
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
            for _ in 0..5 {
                let word = Sha256Word {
                    var: Composer::<Fr>::null(),
                    hvar: Composer::<Fr>::null(),
                    lvar: Composer::<Fr>::null(),
                    hvar_spread: Composer::<Fr>::null(),
                    lvar_spread: Composer::<Fr>::null(),
                };
                sha256_all_public_data.push(word);
            }
            let pad_value = Fr::from(800u64);
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
            sha256_no_padding_words_var_fixed_length(&mut cs, &sha256_all_public_data, 2).unwrap();

        let public_inputs_hash =
            sha256_collect_8_outputs_to_field(&mut cs, &all_public_hash).unwrap();

        cs.set_variable_public_input(public_inputs_hash);

        cs
    }
}
