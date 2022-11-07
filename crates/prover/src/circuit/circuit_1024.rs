use plonk::ark_bn254::Fr;
use plonk::ark_ff::{One, Zero};

use email_parser::types::PrivateInputs;
use plonk::{
    sha256::{
        sha256_collect_8_outputs_to_2_128bits, sha256_collect_8_outputs_to_field,
        sha256_no_padding_words_var, Sha256Word,
    },
    Composer,
};

use crate::{error::ProverError, utils::padding_bytes};

pub struct Email1024CircuitInput {
    pub email_header_bytes_padding: Vec<u8>,
    pub email_addr_pepper_bytes_padding: Vec<u8>,
    pub email_header_pub_match: Vec<u8>,
    pub from_left_index: u32,
    pub from_len: u32,
    pub from_padding_len: u32,
    pub header_padding_len: u32,
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

        // padding email header
        let email_header_bytes_padding = padding_bytes(&private_inputs.email_header);
        let email_addr_pepper_bytes_padding = padding_bytes(&email_addr_pepper_bytes);

        // set any byte of "pub match string" to "0" is OK.
        // (you can only remain bytes for format checking, set all other bytes to 0)
        let mut email_header_pub_match = email_header_bytes_padding.clone();

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
        let from_padding_len = (email_addr_pepper_bytes_padding.len() / 64) as u32;
        let header_padding_len = (email_header_bytes_padding.len() / 64) as u32;

        Ok(Self {
            email_header_bytes_padding,
            email_addr_pepper_bytes_padding,
            email_header_pub_match,
            from_left_index,
            from_len,
            from_padding_len,
            header_padding_len,
        })
    }

    pub fn synthesize(&self) -> Composer<Fr> {
        // new '5 column' circuit
        let mut cs = Composer::new(5);

        let (email_header_max_lens, email_addr_max_lens) = Self::parameters();

        // alloc variables for "a"
        let mut email_header_vars = vec![];
        for e in &self.email_header_bytes_padding {
            email_header_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = email_header_vars.len();
        // padding "a" to max_lens
        for _ in n..email_header_max_lens {
            email_header_vars.push(cs.alloc(Fr::zero()));
        }

        // alloc variables for "b"
        let mut email_addr_pepper_vars = vec![];
        for e in &self.email_addr_pepper_bytes_padding {
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
        let email_header_data_len = cs.alloc(Fr::from(self.header_padding_len));
        // "sample_b_bytes_padding" is 2*512 bits, so we need the index to output correct sha256
        let email_addr_pepper_data_len = cs.alloc(Fr::from(self.from_padding_len));
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
            concat_hash_data.push(Sha256Word::new_from_32bits_var(&mut cs, v).unwrap());
        }
        // should be public, we will handle it later in the hash.
        let mask_hash_len = cs.alloc(Fr::from(2));
        let mask_hashs =
            sha256_no_padding_words_var(&mut cs, &concat_hash_data, mask_hash_len, 2).unwrap();

        let mask_r = sha256_collect_8_outputs_to_field(&mut cs, &mask_hashs).unwrap();

        // private substring check. use sha256(a_hash|b_hash) as mask_r
        let (output_bits_a, output_bits_b) = cs
            .add_substring_mask_poly_1024(&email_header_vars, &email_addr_pepper_vars, mask_r, l, m)
            .unwrap();

        // pub match "a"
        // public string to be matched
        let mut email_header_pubmatch_vars = vec![];
        for e in &self.email_header_pub_match {
            email_header_pubmatch_vars.push(cs.alloc(Fr::from(*e)));
        }
        // padding to max_lens
        let n = email_header_pubmatch_vars.len();
        for _ in n..email_header_max_lens {
            email_header_pubmatch_vars.push(cs.alloc(Fr::zero()));
        }

        // public string match.
        cs.add_public_match(
            &email_header_vars,
            &email_header_pubmatch_vars,
            email_header_max_lens,
        )
        .unwrap();

        // should make 'match string' public. here we use sha256 to make public_inputs smaller
        let mut sha256_pubmatch_data = vec![];
        for vs in email_header_pubmatch_vars.chunks(4) {
            sha256_pubmatch_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }
        let pubmatch_hash = sha256_no_padding_words_var(
            &mut cs,
            &sha256_pubmatch_data,
            email_header_data_len,
            email_header_max_lens * 8 / 512,
        )
        .unwrap();

        let email_header_hash128 =
            sha256_collect_8_outputs_to_2_128bits(&mut cs, &email_header_hash).unwrap();
        let email_addr_pepper_hash128 =
            sha256_collect_8_outputs_to_2_128bits(&mut cs, &email_addr_pepper_hash).unwrap();
        let pubmatch_hash128 =
            sha256_collect_8_outputs_to_2_128bits(&mut cs, &pubmatch_hash).unwrap();

        // gen pub_inputs
        let pub_out01 = cs.get_assignment(email_header_data_len)
            * Fr::from(1u128 << 64)
            * Fr::from(1u128 << 64)
            + cs.get_assignment(email_header_hash128[0]);
        let pub_out01_var = cs.alloc_input(pub_out01);
        cs.poly_gate(
            vec![
                (pub_out01_var, -Fr::one()),
                (
                    email_header_data_len,
                    Fr::from(1u128 << 64) * Fr::from(1u128 << 64),
                ),
                (email_header_hash128[0], Fr::one()),
            ],
            Fr::zero(),
            Fr::zero(),
        );
        let pub_out02 =
            cs.get_assignment(mask_hash_len) * Fr::from(1u128 << 64) * Fr::from(1u128 << 64)
                + cs.get_assignment(email_header_hash128[1]);
        let pub_out02_var = cs.alloc_input(pub_out02);
        cs.poly_gate(
            vec![
                (pub_out02_var, -Fr::one()),
                (mask_hash_len, Fr::from(1u128 << 64) * Fr::from(1u128 << 64)),
                (email_header_hash128[1], Fr::one()),
            ],
            Fr::zero(),
            Fr::zero(),
        );
        let pub_out03 = cs.get_assignment(email_addr_pepper_data_len)
            * Fr::from(1u128 << 64)
            * Fr::from(1u128 << 64)
            + cs.get_assignment(email_addr_pepper_hash128[0]);
        let pub_out03_var = cs.alloc_input(pub_out03);
        cs.poly_gate(
            vec![
                (pub_out03_var, -Fr::one()),
                (
                    email_addr_pepper_data_len,
                    Fr::from(1u128 << 64) * Fr::from(1u128 << 64),
                ),
                (email_addr_pepper_hash128[0], Fr::one()),
            ],
            Fr::zero(),
            Fr::zero(),
        );
        cs.set_variable_public_input(email_addr_pepper_hash128[1]);
        for v in output_bits_a {
            cs.set_variable_public_input(v);
        }
        cs.set_variable_public_input(output_bits_b);
        cs.set_variable_public_input(pubmatch_hash128[0]);
        cs.set_variable_public_input(pubmatch_hash128[1]);

        // for elem in &email_header_hash128 {
        //     let value = cs.get_assignment(*elem);
        //     log::trace!("a{}", value);
        // }
        // for elem in &email_addr_pepper_hash128 {
        //     let value = cs.get_assignment(*elem);
        //     log::trace!("b{}", value);
        // }
        // for elem in &pubmatch_hash128 {
        //     let value = cs.get_assignment(*elem);
        //     log::trace!("pubmatch{}", value);
        // }

        cs
    }
}
