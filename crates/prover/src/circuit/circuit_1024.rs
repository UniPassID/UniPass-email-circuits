use plonk::ark_bn254::Fr;
use plonk::ark_ff::{One, Zero};

use email_parser::types::PrivateInputs;
use plonk::sha256::sha256_no_padding_words_var_fixed_length;
use plonk::{
    sha256::{sha256_collect_8_outputs_to_field, sha256_no_padding_words_var, Sha256Word},
    Composer,
};

use crate::utils::convert_sha256words;
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

        // num of 512bits. we need the index to output correct sha256.
        let email_header_data_len = cs.alloc(Fr::from(header_padding_len));
        // num of 512bits. we need the index to output correct sha256.
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

        let (bit_location_a, bit_location_b) = cs
            .gen_bit_location_for_substr(l, m, email_header_max_lens, email_addr_max_lens)
            .unwrap();

        let output_words_a = cs
            .collect_bit_location_for_sha256(email_header_max_lens, &bit_location_a)
            .unwrap();
        let output_words_b = cs
            .collect_bit_location_for_sha256(email_addr_max_lens, &bit_location_b)
            .unwrap();

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

        // gen pub_inputs
        // hash all public. 2016 bits (256|256|1024|192|256|16|16)
        // sha256(a_hash|b_hash|a_bits_location|b_bits_location|sha256(pub_string)|header_len|addr_len)

        // cal sha256(pub_string)
        let mut sha256_pubstr_data = vec![];
        for vs in email_header_pubmatch_vars.chunks(4) {
            // "Sha256Word" is the type we need in the sha256, each contain 32bits
            sha256_pubstr_data
                .push(Sha256Word::new_from_8bits(&mut cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
        }
        // get the hash
        let pubstr_hash = sha256_no_padding_words_var(
            &mut cs,
            &sha256_pubstr_data,
            email_header_data_len,
            email_header_max_lens * 8 / 512,
        )
        .unwrap();

        // cal sha256(a_hash|b_hash|a_bits_location|b_bits_location|sha256(pub_string)|header_len|addr_len)
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
        for wd in pubstr_hash {
            let word = Sha256Word {
                var: wd,
                hvar: Composer::<Fr>::null(),
                lvar: Composer::<Fr>::null(),
                hvar_spread: Composer::<Fr>::null(),
                lvar_spread: Composer::<Fr>::null(),
            };
            sha256_all_public_data.push(word);
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
        // padding (480bits + 64bits)
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
            for _ in 0..15 {
                let word = Sha256Word {
                    var: Composer::<Fr>::null(),
                    hvar: Composer::<Fr>::null(),
                    lvar: Composer::<Fr>::null(),
                    hvar_spread: Composer::<Fr>::null(),
                    lvar_spread: Composer::<Fr>::null(),
                };
                sha256_all_public_data.push(word);
            }
            let pad_value = Fr::from(2016u64);
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
            sha256_no_padding_words_var_fixed_length(&mut cs, &sha256_all_public_data, 5).unwrap();

        let public_inputs_hash =
            sha256_collect_8_outputs_to_field(&mut cs, &all_public_hash).unwrap();

        cs.set_variable_public_input(public_inputs_hash);

        // use 'public inputs' as mask_r
        let mask_r = public_inputs_hash;

        // private substring check.
        cs.add_substring_mask_poly_return_words(
            &email_header_vars,
            &email_addr_pepper_vars,
            &bit_location_a,
            &bit_location_b,
            mask_r,
            l,
            m,
            email_header_max_lens,
            email_addr_max_lens,
        )
        .unwrap();

        // pub match "a"
        // public string match.
        cs.add_public_match_no_custom_gate(
            &email_header_vars,
            &email_header_pubmatch_vars,
            email_header_max_lens,
        );

        cs
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use email_parser::parser::parse_email;
    use plonk::{
        ark_bn254::{self, Fr},
        ark_std::test_rng,
        kzg10::PCKey,
        prover,
        verifier::Verifier,
        Composer, Error, Field, GeneralEvaluationDomain,
    };
    use sha2::Digest;

    use crate::{
        circuit::circuit_1024::Email1024CircuitInput,
        utils::{bit_location, convert_public_inputs, padding_len, to_0x_hex},
    };

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
    fn test_email1024_circuit() {
        let emails = [
            r#"X-Mailgun-Incoming: Yes
X-Envelope-From: <kylexyxu@gmail.com>
Received: from mail-qt1-f174.google.com (mail-qt1-f174.google.com [209.85.160.174])
 by mxa.mailgun.org with ESMTP id 61b9c388.7f13fb80deb0-smtp-in-n03;
 Wed, 15 Dec 2021 10:29:28 -0000 (UTC)
Received: by mail-qt1-f174.google.com with SMTP id o17so21295954qtk.1
        for <bot@mail.unipass.id>; Wed, 15 Dec 2021 02:29:27 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=content-transfer-encoding:from:mime-version:date:subject:message-id
         :to;
        bh=JLBZyNo0MYCImTHsmCgwi7GM7VKpG1T7SyqXznXhau0=;
        b=JQrQ/5gXpvqodj/0XMN11WOAouz16D8p4vHdhS2TYMN7ea6dgNbXv64XBgo+2sjb7R
         37jYbUz5xL39i6QJdBw9GbtqkQStyGLOkSpfT4HINU58RcXvpW08cCa72nQJbk1bVe8F
         wS3QDInAfy0Tuul6pI7soLd7WDS8k+8Oip8aeUyoR26y/13QIoYWzIF6QIA/o6+Az/QU
         OdOXdaWm4kxZNciMyNsw1aMoAfhkUtad9RNv4gRwGFNQbfF9trtiiVEfZarJr8stvo5l
         F+vnGcgyRY8K5Mu9MrlkIp+6YrJjZw5nbJSiQbsQCdiSEzGnD4zLg6lddEm14hT1084I
         bViQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:content-transfer-encoding:from:mime-version:date
         :subject:message-id:to;
        bh=JLBZyNo0MYCImTHsmCgwi7GM7VKpG1T7SyqXznXhau0=;
        b=OdxlTdOeVr0rOdUK6gWy2iybKQmQNS8SzOIdtWXsHuKa0O93fBzJiMKgWZBPmafiCc
         F8NblbBjtGeBIT2KGya5TxyyzuuQWBYLVsq8SUeyqjod3h1J1EHzfpvFxpKhQYwithrL
         fGaHLN96N1WIupZ46OEkQ8nWX3CEWhRdl5wjIS93cD4KZasjBIj7vfO/cA/auicay+Y3
         RGVY8OfEQcB/n2orxISH8aqv+oeSzZuuctnl1MHojbEyelqQVgsLcSAYz4mSXVcd1F/f
         /PpAGjSr9ff72LsC64SEKBW8gsD8TLoRqOP/k2xTeYvoWRAcCRNCDXj91BMlaf2I0NBj
         9XRA==
X-Gm-Message-State: AOAM531SKf9KJpsBSCdbSPDhtW/jDtgvxU7UNzDLciBhAhaFKoB4Xikj
	pgR/OQN1bTxB1yHdjKEKOrLOR/XnBPTLlMjTROWccQ==
X-Google-Smtp-Source: ABdhPJxAIFOx3IgE5rEIQVlWY64ivxlpuch+jL1NTEQWE4PXLteou/Plv3sI/DbhFmaSYl0z40UMFg==
X-Received: by 2002:a05:622a:1705:: with SMTP id h5mr10892863qtk.331.1639564167129;
        Wed, 15 Dec 2021 02:29:27 -0800 (PST)
Return-Path: <kylexyxu@gmail.com>
Received: from smtpclient.apple (bras-base-mtrlpq4706w-grc-07-174-93-163-70.dsl.bell.ca. [174.93.163.70])
        by smtp.gmail.com with ESMTPSA id b11sm1100064qtx.85.2021.12.15.02.29.26
        for <bot@mail.unipass.id>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Dec 2021 02:29:26 -0800 (PST)
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable
From: kyle xu <kylexyxu@gmail.com>
Mime-Version: 1.0 (1.0)
Date: Wed, 15 Dec 2021 18:29:23 +0800
Subject: UP0xd3d9695e34088a17064a9ebf38cabc80c26dff7249b3e45c373c2e9b160a0d07
Message-Id: <0248A5E5-2DBF-4D9D-ABEC-F40E76F83099@gmail.com>
To: bot@mail.unipass.id
X-Mailer: iPhone Mail (18E212)

 Unipass Test"#,
            r#"X-Mailgun-Incoming: Yes
X-Envelope-From: <cryptostwich@gmail.com>
Received: from mail-pl1-f194.google.com (mail-pl1-f194.google.com [209.85.214.194])
 by mxa.mailgun.org with ESMTP id 623db2ad.7f9467135830-smtp-in-n03;
 Fri, 25 Mar 2022 12:16:45 -0000 (UTC)
Received: by mail-pl1-f194.google.com with SMTP id p17so7821888plo.9
        for <bot@mail.unipass.id>; Fri, 25 Mar 2022 05:16:44 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to;
        bh=aQkTQS2qFskx9CTMPnzluLHfF9WINt9SvB7x5FxC0MU=;
        b=hvhBdlpSBKGZQtFoUtU90bOjmwEiGRdjrYiRVQrglRknm0RTnJZ/MMwt22wyAh2PRA
         bcqGxB4BTBH7idvN+Dva96/gnjMY+JfNptcc1ndiDsUXQHnC35zBn0+dNxb8Y1DDkLLj
         fbMdEhW+WSD5uEVvRX4JC2EhL0Px3+VD74Vc9AVtEAt1/JIr1JTZgf01eCMiAZqvga/i
         SKEJ9qEMigx+fiXWHujEGgXgcKj8zFaLkwcWsnzX+VUzMhtsE1d8t1OUV4BnqGte/ej4
         /zHmzXW0fMponGoorqoZTI6tnMfWbSdJKqhtDKIhuLa1ORuOhqIBtmy3UWo3vLiBlNLX
         KStQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;
        bh=aQkTQS2qFskx9CTMPnzluLHfF9WINt9SvB7x5FxC0MU=;
        b=THd42HndgngEwhpY5Pasm9HKgtcXrTVLjMApb1avi1LkutsQuxGtSd0gtICkSpBq86
         DRVcLg+96H0+NcStHcyXyxnvN8ulKY8jhoaCohH/sCfcO3X2azTbLcj+ic6E84/rvrKQ
         rfxOnAT3v/elDbx+483Z99w8mziNpFzLQN3fqmsuqT/+L1yCCGCBAcQmixG7UbpaIthK
         3ElXjYLEXJz+NwB5WDn/hkEgHBzhZH7mHF5Zrisih43/A8g4I9cigiA8HXRYRxhk79oJ
         EQ24vq6NwmAJZEVLKgvZ766NUPW2g2ojrFqV1SzbgLAx1rovZClFaqvbj7OAeKBUobYx
         DR2A==
X-Gm-Message-State: AOAM5319qtvnHvOWuQBarWEgC3lF1zetmrVYizOgMKkA50dj19oMM7u/
	rEpkA+anWEDSPaaAYeMxdGnRHOEjBsNn9j32khYPI3tO2WQ=
X-Google-Smtp-Source: ABdhPJx82G0Sps/op0CqX6vdRyc7h2oBcloFHd+U6r+N+uWwvgj8IZtgcgjhUegFzkQi8SVBJg+gLTAVxnF77kR9ga0=
X-Received: by 2002:a17:903:2406:b0:14d:2f71:2e6d with SMTP id
 e6-20020a170903240600b0014d2f712e6dmr11107827plo.98.1648210604337; Fri, 25
 Mar 2022 05:16:44 -0700 (PDT)
MIME-Version: 1.0
From: Jason Chai <cryptostwich@gmail.com>
Date: Fri, 25 Mar 2022 20:16:31 +0800
Message-ID: <CAF5xp0mCOyj2O6-gs8sQn6wYLgx_=x6T1JTS6oymy18mC7CP7w@mail.gmail.com>
Subject: UP0x92911dbe1941804f3fd6401187779ec1336810de97c52bcc4c2d6fe06f838761
To: bot@mail.unipass.id
Content-Type: multipart/alternative; boundary="000000000000964f7205db09ef67"

 Unipass Test
 "#,
            r#"X-Mailgun-Incoming: Yes
X-Envelope-From: <cryptostwich@gmail.com>
Received: from mail-pl1-f194.google.com (mail-pl1-f194.google.com [209.85.214.194])
 by mxa.mailgun.org with ESMTP id 623db2ad.7f9467135830-smtp-in-n03;
 Fri, 25 Mar 2022 12:16:45 -0000 (UTC)
Received: by mail-pl1-f194.google.com with SMTP id p17so7821888plo.9
        for <bot@mail.unipass.id>; Fri, 25 Mar 2022 05:16:44 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to;
        bh=aQkTQS2qFskx9CTMPnzluLHfF9WINt9SvB7x5FxC0MU=;
        b=hvhBdlpSBKGZQtFoUtU90bOjmwEiGRdjrYiRVQrglRknm0RTnJZ/MMwt22wyAh2PRA
         bcqGxB4BTBH7idvN+Dva96/gnjMY+JfNptcc1ndiDsUXQHnC35zBn0+dNxb8Y1DDkLLj
         fbMdEhW+WSD5uEVvRX4JC2EhL0Px3+VD74Vc9AVtEAt1/JIr1JTZgf01eCMiAZqvga/i
         SKEJ9qEMigx+fiXWHujEGgXgcKj8zFaLkwcWsnzX+VUzMhtsE1d8t1OUV4BnqGte/ej4
         /zHmzXW0fMponGoorqoZTI6tnMfWbSdJKqhtDKIhuLa1ORuOhqIBtmy3UWo3vLiBlNLX
         KStQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;
        bh=aQkTQS2qFskx9CTMPnzluLHfF9WINt9SvB7x5FxC0MU=;
        b=THd42HndgngEwhpY5Pasm9HKgtcXrTVLjMApb1avi1LkutsQuxGtSd0gtICkSpBq86
         DRVcLg+96H0+NcStHcyXyxnvN8ulKY8jhoaCohH/sCfcO3X2azTbLcj+ic6E84/rvrKQ
         rfxOnAT3v/elDbx+483Z99w8mziNpFzLQN3fqmsuqT/+L1yCCGCBAcQmixG7UbpaIthK
         3ElXjYLEXJz+NwB5WDn/hkEgHBzhZH7mHF5Zrisih43/A8g4I9cigiA8HXRYRxhk79oJ
         EQ24vq6NwmAJZEVLKgvZ766NUPW2g2ojrFqV1SzbgLAx1rovZClFaqvbj7OAeKBUobYx
         DR2A==
X-Gm-Message-State: AOAM5319qtvnHvOWuQBarWEgC3lF1zetmrVYizOgMKkA50dj19oMM7u/
	rEpkA+anWEDSPaaAYeMxdGnRHOEjBsNn9j32khYPI3tO2WQ=
X-Google-Smtp-Source: ABdhPJx82G0Sps/op0CqX6vdRyc7h2oBcloFHd+U6r+N+uWwvgj8IZtgcgjhUegFzkQi8SVBJg+gLTAVxnF77kR9ga0=
X-Received: by 2002:a17:903:2406:b0:14d:2f71:2e6d with SMTP id
 e6-20020a170903240600b0014d2f712e6dmr11107827plo.98.1648210604337; Fri, 25
 Mar 2022 05:16:44 -0700 (PDT)
MIME-Version: 1.0
From: Jason Chai <cryptostwich@gmail.com>
Date: Fri, 25 Mar 2022 20:16:31 +0800
Message-ID: <CAF5xp0mCOyj2O6-gs8sQn6wYLgx_=x6T1JTS6oymy18mC7CP7w@mail.gmail.com>
Subject: UP0x92911dbe1941804f3fd6401187779ec1336810de97c52bcc4c2d6fe06f838761
To: bot@mail.unipass.id
Content-Type: multipart/alternative; boundary="000000000000964f7205db09ef67"

 Unipass Test
 "#,
        ];
        // append 32bytes pepper
        let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
        let from_pepper = hex::decode(pepper).unwrap();

        let mut index = 0;
        for email_bytes in emails {
            let (email_public_inputs, email_private_inputs) =
                parse_email(email_bytes.as_bytes(), from_pepper.clone()).unwrap();

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

            let (bit_location_a, bit_location_b) =
                bit_location(from_left_index as u32, addr_len, 1024, 192);

            let mut sha256_input: Vec<u8> = vec![];
            sha256_input.extend(&email_public_inputs.header_hash);
            sha256_input.extend(&email_public_inputs.from_hash);

            sha256_input.extend(bit_location_a);
            sha256_input.extend(bit_location_b);

            sha256_input.extend(sha2::Sha256::digest(&circuit.email_header_pub_match).to_vec());
            sha256_input.extend((padding_len(header_len) as u16 / 64).to_be_bytes());
            sha256_input.extend((padding_len(addr_len + 32) as u16 / 64).to_be_bytes());

            let mut public_input = sha2::Sha256::digest(&sha256_input).to_vec();
            public_input[0] = public_input[0] & 0x1f;
            println!("public_input: {}", to_0x_hex(&public_input));

            println!("[test_email1024_circuit] circuit construct finish");
            let mut cs = circuit.synthesize();
            println!("[test_email1024_circuit] synthesize finish");

            test_prove_verify(&mut cs, vec![Fr::from_be_bytes_mod_order(&public_input)]).unwrap();
        }
    }
}
