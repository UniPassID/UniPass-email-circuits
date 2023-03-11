use std::time::Instant;

use crate::{
    circuit::{
        base64::{base64url_encode_gadget, BASE64URL_ENCODE_CHARS},
        circuit_1024::Email1024CircuitInput,
        circuit_2048::Email2048CircuitInput,
        circuit_2048_triple::Email2048TripleCircuitInput,
        openid::{
            OpenIdCircuit, EMAIL_ADDR_MAX_LEN, HEADER_BASE64_MAX_LEN, ID_TOKEN_MAX_LEN,
            PAYLOAD_BASE64_MAX_LEN, PAYLOAD_RAW_MAX_LEN,
        },
    },
    utils::{bit_location, convert_public_inputs, padding_len, to_0x_hex},
};

use email_parser::parser::parse_email;
use plonk::{
    ark_bn254::{self, Fr},
    ark_std::{test_rng, Zero},
    composer::Table,
    kzg10::PCKey,
    prover,
    verifier::Verifier,
    Composer, Error, Field, GeneralEvaluationDomain,
};
use sha2::Digest;

fn test_prove_verify(cs: &mut Composer<Fr>, expected_public_input: Vec<Fr>) -> Result<(), Error> {
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
    let mut prover = prover::Prover::<Fr, GeneralEvaluationDomain<Fr>, ark_bn254::Bn254>::new(pk);

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

const TEST_EMAILS: [&str; 3] = [
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

#[test]
fn test_email1024_circuit() {
    // append 32bytes pepper
    let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    let from_pepper = hex::decode(pepper).unwrap();

    let mut index = 0;
    for email_bytes in TEST_EMAILS {
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

#[test]
fn test_email2048_circuit() {
    // append 32bytes pepper
    let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    let from_pepper = hex::decode(pepper).unwrap();
    let mut index = 0;
    for email_bytes in TEST_EMAILS {
        let (email_public_inputs, email_private_inputs) =
            parse_email(email_bytes.as_bytes(), from_pepper.clone()).unwrap();
        index += 1;

        let header_len = email_private_inputs.email_header.len() as u32;
        let addr_len = (email_private_inputs.from_right_index
            - email_private_inputs.from_left_index
            + 1) as u32;
        let from_left_index = email_private_inputs.from_left_index;

        println!("----------------------------------------------------------------");
        println!("Test circuit 2048-{}", index);

        let circuit = Email2048CircuitInput::new(email_private_inputs).unwrap();
        println!("[main] circuit construct finish");
        let mut cs = circuit.synthesize();
        println!("[main] synthesize finish");

        let (bit_location_a, bit_location_b) =
            bit_location(from_left_index as u32, addr_len, 2048, 192);

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

        test_prove_verify(&mut cs, vec![Fr::from_be_bytes_mod_order(&public_input)]).unwrap();
    }
}

#[test]
fn test_email2048tri_circuit() {
    // append 32bytes pepper
    let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    let from_pepper = hex::decode(pepper).unwrap();

    let mut all_email_public_inputs = vec![];
    let mut all_email_private_inputs = vec![];
    for email_bytes in TEST_EMAILS {
        let (email_public_inputs, email_private_inputs) =
            parse_email(email_bytes.as_bytes(), from_pepper.clone()).unwrap();

        all_email_public_inputs.push(email_public_inputs);
        all_email_private_inputs.push(email_private_inputs);
    }
    println!("----------------------------------------------------------------");
    println!("Test circuit 2048triple");

    let mut sha256_input: Vec<u8> = vec![];
    let circuit =
        Email2048TripleCircuitInput::new((&all_email_private_inputs[0..3]).to_vec()).unwrap();

    for (i, (email_public_inputs, email_private_inputs)) in all_email_public_inputs
        .iter()
        .zip(&all_email_private_inputs)
        .enumerate()
    {
        let header_len = email_private_inputs.email_header.len() as u32;
        let addr_len = (email_private_inputs.from_right_index
            - email_private_inputs.from_left_index
            + 1) as u32;
        let from_left_index = email_private_inputs.from_left_index;
        let (bit_location_a, bit_location_b) =
            bit_location(from_left_index as u32, addr_len, 2048, 192);
        let mut r: Vec<u8> = vec![];
        r.extend(&email_public_inputs.header_hash);
        r.extend(&email_public_inputs.from_hash);
        r.extend(&bit_location_a);
        r.extend(&bit_location_b);
        sha256_input.extend(sha2::Sha256::digest(&r.to_vec()));
        sha256_input.extend(sha2::Sha256::digest(&circuit.email_header_pub_matches[i]).to_vec());
        sha256_input.extend((padding_len(header_len) as u16 / 64).to_be_bytes());
        sha256_input.extend((padding_len(addr_len + 32) as u16 / 64).to_be_bytes());
    }

    let mut public_input = sha2::Sha256::digest(&sha256_input).to_vec();
    public_input[0] = public_input[0] & 0x1f;
    println!("public_input: {}", to_0x_hex(&public_input));

    println!("[test_email2048tri_circuit] circuit construct finish");
    let mut cs = circuit.synthesize();
    println!("[test_email2048tri_circuit] synthesize finish");

    test_prove_verify(&mut cs, vec![Fr::from_be_bytes_mod_order(&public_input)]).unwrap();
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
        let email_addr_peper_hash = sha2::Sha256::digest(&circuit.email_addr_pepper_bytes).to_vec();

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

pub fn base64url_encode(data: &[u8]) -> String {
    let data_len = data.len();
    let mut encoded_len = data_len / 3 * 4;
    if data_len % 3 == 1 {
        encoded_len += 2;
    } else if data_len % 3 == 2 {
        encoded_len += 3;
    }
    let mut output = String::with_capacity(encoded_len);

    let mut index = 0;
    while index < data_len {
        let char1 = data[index];
        index += 1;
        let out1 = char1 >> 2;
        output.push(BASE64URL_ENCODE_CHARS[out1 as usize].into());
        if index == data_len {
            let out2 = (char1 & 0x3) << 4;
            output.push(BASE64URL_ENCODE_CHARS[out2 as usize].into());
            return output;
        }

        let char2 = data[index];
        index += 1;
        let out2 = (char1 & 0x3) << 4 | (char2 & 0xf0) >> 4;

        output.push(BASE64URL_ENCODE_CHARS[out2 as usize].into());
        if index == data_len {
            let out3 = (char2 & 0xf) << 2;
            output.push(BASE64URL_ENCODE_CHARS[out3 as usize].into());
            return output;
        }

        let char3 = data[index];
        index += 1;
        let out3 = (char2 & 0xf) << 2 | (char3 & 0xc0) >> 6;

        output.push(BASE64URL_ENCODE_CHARS[out3 as usize].into());
        let out4 = char3 & 0x3f;
        output.push(BASE64URL_ENCODE_CHARS[out4 as usize].into());
    }
    return output;
}

pub struct Base64TestCircuit {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}

impl Base64TestCircuit {
    pub fn synthesize(&self) -> Composer<Fr> {
        // new '5 column' circuit
        let mut cs = Composer::new(5, false);

        let _ = cs.add_table(Table::spread_table(2));

        let _ = cs.add_table(Table::spread_table_2in1(5, 4));
        let _ = cs.add_table(Table::spread_table_2in1(7, 6));

        let max_input_len = 1026;
        let max_output_len = 1368;

        let mut input_vars = vec![];
        for e in &self.input {
            input_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = input_vars.len();
        for _ in n..max_input_len {
            input_vars.push(cs.alloc(Fr::zero()));
        }

        let mut expected_output_vars = vec![];
        for e in &self.output {
            expected_output_vars.push(cs.alloc(Fr::from(*e)));
        }
        let n = expected_output_vars.len();
        for _ in n..max_output_len {
            expected_output_vars.push(cs.alloc(Fr::from(b'A')));
        }

        let output_vars = base64url_encode_gadget(&mut cs, &input_vars, max_input_len).unwrap();
        println!("output len: {}", output_vars.len());
        for i in 0..1368 {
            let values = cs.get_assignments(&[expected_output_vars[i], output_vars[i]]);
            if values[0] != values[1] {
                println!("{:?}", values);
                panic!("not equal");
            }
            cs.enforce_eq(expected_output_vars[i], output_vars[i]);
        }

        let output_str = cs.get_assignments(&output_vars);
        let output_str: Vec<_> = output_str
            .into_iter()
            .map(|a| a.into_repr().as_ref()[0] as u8)
            .collect();

        println!("output str: {}", String::from_utf8_lossy(&output_str));
        cs
    }
}

#[test]
fn test_base64url_gadget() {
    let input = b"eiiieskli8%&**9";
    let output = base64url_encode(input);
    println!("output: {}", output);
    let circuit = Base64TestCircuit {
        input: input.to_vec(),
        output: output.as_bytes().to_vec(),
    };

    let mut cs = circuit.synthesize();
    let public_input = cs.compute_public_input();
    println!("cs.size() {}", cs.size());
    println!("cs.table_size() {}", cs.table_size());
    println!("cs.sorted_size() {}", cs.sorted_size());

    let rng = &mut test_rng();

    println!("time start:");
    let start = Instant::now();
    println!("compute_prover_key...");
    let pk = cs
        .compute_prover_key::<GeneralEvaluationDomain<Fr>>()
        .unwrap();
    println!("pk.domain_size() {}", pk.domain_size());
    println!("compute_prover_key...done");
    let pckey = PCKey::<ark_bn254::Bn254>::setup(pk.domain_size() + pk.program_width + 6, rng);
    println!("pckey.max_degree() {}", pckey.max_degree());
    let mut prover = prover::Prover::<Fr, GeneralEvaluationDomain<Fr>, ark_bn254::Bn254>::new(pk);

    println!("init_comms...");
    let verifier_comms = prover.init_comms(&pckey);
    println!("init_comms...done");
    println!("time cost: {:?} ms", start.elapsed().as_millis()); // ms
    let mut verifier = Verifier::new(&prover, &public_input, &verifier_comms);

    println!("prove start:");
    let start = Instant::now();
    let proof = prover.prove(&mut cs, &pckey, rng).unwrap();
    println!("prove time cost: {:?} ms", start.elapsed().as_millis()); // ms

    let sha256_of_srs = pckey.sha256_of_srs();
    println!("verify start:");
    let start = Instant::now();
    let res = verifier.verify(&pckey.vk, &proof, &sha256_of_srs);
    println!("verify result: {}", res);
    assert!(res);
    println!("verify time cost: {:?} ms", start.elapsed().as_millis()); // ms
}
