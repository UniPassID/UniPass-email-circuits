use std::time::Instant;

use plonk::ark_bn254::{Bn254, Fr};
use plonk::ark_serialize::Write;
use plonk::kzg10::PCKey;
use plonk::Field;

use email_parser::parser::parse_email;
use plonk::{prover::Prover, verifier::Verifier, GeneralEvaluationDomain};
use prover::circuit::circuit_2048_triple::Email2048TripleCircuitInput;
use prover::parameters::store_verifier_comms;
use prover::types::ContractTripleInput;
use prover::utils::{bit_location, padding_len};
use prover::utils::{convert_public_inputs, to_0x_hex};
use rand::RngCore;
use sha2::Digest;

pub fn test_2048tri<R: RngCore>(pckey: &PCKey<Bn254>, from_pepper: &[u8], rng: &mut R) {
    let mut pk_2048 = None;
    let mut verifier_comms_2048 = None;

    // let dirs = std::fs::read_dir("test_data/emails").unwrap();
    let emails = vec![
        r#"X-Mailgun-Incoming: Yes
X-Envelope-From: <shubh3304@gmail.com>
Received: from mail-yb1-f174.google.com (mail-yb1-f174.google.com [209.85.219.174])
 by mxa.mailgun.org with ESMTP id 61b9c3d8.7fd969484730-smtp-in-n01;
 Wed, 15 Dec 2021 10:30:48 -0000 (UTC)
Received: by mail-yb1-f174.google.com with SMTP id f186so53838837ybg.2
        for <bot@mail.unipass.id>; Wed, 15 Dec 2021 02:30:48 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to;
        bh=3+et0d137uISRa50mx4QOkNzH7iuNfuRytlfUpGBa5Y=;
        b=XaoOyEqPuNXItU0NGIY/TW5Ek7YNG9SsZnyWm6+xwnoWp6FycH9kG3d4YC33KeAi8m
         AWRLCSrmyUGicaf89oE0+ol8jVLmWwOa734foNlXf3ef9Kq9mwXNa+2QX8GQQmT8znE9
         MP6pbN9SbyDd3ChvPJ6XPUVY9HRWzdjqGejr/DaCNCUFrzrLLo3MBMb32YUkbP29zWDI
         WCuHIL223+VyE78yXLH69k42YBGh14knsfLQrLwjbGyzk49lsNiDGqBv6D194Jsp7XlE
         PoNeC0Mg7VwM5KBL6XJK7fhqYfEeYkeA0g9OhqZhb5ybaQMgTIeWXvJnIRdjHJesM8uT
         4LlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;
        bh=3+et0d137uISRa50mx4QOkNzH7iuNfuRytlfUpGBa5Y=;
        b=yLQvEDW0VKHrQV6BiK/83WXRGAnZGCgeSQd9NMfMgHlkaMW11BXenesX+1a7kNy7q1
         4ZCdooWHymidCMXGcarrmaw78pvcvcAF/axX2gKt+plPRnOASarx1bmHZdsYWtTvDNpm
         eVugUpE6/Ztwugr+ioj6Q5sMvnRa5rslRS+B7EJI+HtkpXlQmYpB0iaFHKUqgyZ0gbPn
         LfM0TQDj0Ee3lTqW7B41+JBn142zgY5cKaSNIJ7oHdRs8xsdvuk4JbI5Uwp8rQ03E5qa
         0ClQ3QMbddmZy+h7A2CRcjGhwuUcODLI5ysUJaK9KPyCm7Jn5gVN5nHljUK9ARhqiw3x
         MO7g==
X-Gm-Message-State: AOAM5322jciu7DMQDlv1A6Ejx15xTpd++gYGO8vmO0tFEpQ/gP/xLlRv
	aUiS9O7Rk7OCEQYHwBnG4HkRpJ7fX+GGQVTbcvpDTrum
X-Google-Smtp-Source: ABdhPJyIJPAlxTB9Ing3v2qK5wyExwgHKX2XVzSIh0c2ttRWVKvYkGpRbOYna6bD3TOBaplL1E02xRQeUznvRc79fvk=
X-Received: by 2002:a25:d781:: with SMTP id o123mr5267276ybg.666.1639564247657;
 Wed, 15 Dec 2021 02:30:47 -0800 (PST)
MIME-Version: 1.0
From: Shubh Shubh <shubh3304@gmail.com>
Date: Wed, 15 Dec 2021 16:00:35 +0530
Message-ID: <CAEFmmvFmyfYkwhdZwecwdcezr9PicXiGfM657SCoE==dutpZkA@mail.gmail.com>
Subject: UP0xffbdbf79c852e5618a8ef7caf871f55a895f4535c327784f00e4e0ffa7d2dd1f
To: bot@mail.unipass.id
Content-Type: multipart/alternative; boundary="0000000000009170a605d32cccc7"

 Unipass Test"#,
        r#"X-Mailgun-Incoming: Yes
X-Envelope-From: <w382303784@gmail.com>
Received: from mail-ed1-f48.google.com (mail-ed1-f48.google.com [209.85.208.48])
 by mxa.mailgun.org with ESMTP id 61b9c4e2.7fd4523b7cf0-smtp-in-n03;
 Wed, 15 Dec 2021 10:35:14 -0000 (UTC)
Received: by mail-ed1-f48.google.com with SMTP id y12so72130553eda.12
        for <bot@mail.unipass.id>; Wed, 15 Dec 2021 02:35:13 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to;
        bh=4+3VkTaGWVzmpBC+51RLJX0FMnAJ0q95JHD6tjMsTSw=;
        b=ptkBXY+XaKjJv9nLPEDaRr3dmqnEWQSaUYGsk2yb/7588VVrQx1t1/Ettjac0KKtgn
         eBdGtIeGkjYMo7oJMQvyYCOWrL1vcU+zRavqAo8Llc2p2SpeTQijuqo830R16yAfUPUd
         wyk/nDOnJVbsLLR6QLrCXmL5uiifUe3JMjp32NBxbebLJTfSxCH1uE1rBZD8gIriP9uq
         ZuuTLYlFtzFhAsOREjejM0kUCj1zPAnWQ2yOhmLV7rRhp4w3/M4WJL331o+E7HchGf8D
         pDgx4+oyxQfy2NVFYLyeP1wFVCE9oawyQBGhp+0uMZ/Wun0+jnQAsYnA2oCA/tAtKOLF
         40YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;
        bh=4+3VkTaGWVzmpBC+51RLJX0FMnAJ0q95JHD6tjMsTSw=;
        b=MfU9aY943bdExrxNSU4xGxCR+zaMkz2J/EjMu7tBhgJtYZZgOEKeJj18aDg2yQRppJ
         ++W1zDZpj2dMPwssWf5LhviscGdzbzPrx3ULS7OBxtALEbsj8sk63fhBsD+yZyGa7axK
         Hyb1h90axrvPgyrXYxJY9zYdpZk17KTxLo2PTjizx/keLRnuzuUch5HJbkfLee3z56is
         I10cz3J4CdThXXAudMSitCtJ5RJJnEhqp/bf0mDAhnt9NIXwmeEVn1S9WIJ55O26Uvnm
         BVP9lcG8i+o3zuKZjj3spRevG4RbqqUArITnpPqROX+d1F0bfY3xPKOppw6a7+s/uShB
         9zWA==
X-Gm-Message-State: AOAM5303/l7WKs3C5NGVU6DYXv8gqy/usKtmqggjHIsMmPPWqlDoo0sW
	yMmo6X6VdbIk+q5C40SCOUw0AjgC/xIkl4jtQbucTRZzL1M=
X-Google-Smtp-Source: ABdhPJwov7Gz6uZZ195cutTI0sv7n9xkj8Nyy62V1DrXXPpDxJ9KLCKFaKpqUbIEJHxsXdCG2KaXF0gxIdX0aC+sPhM=
X-Received: by 2002:a17:906:3a9b:: with SMTP id y27mr10084188ejd.563.1639564512313;
 Wed, 15 Dec 2021 02:35:12 -0800 (PST)
MIME-Version: 1.0
From: gy wang <w382303784@gmail.com>
Date: Wed, 15 Dec 2021 18:35:01 +0800
Message-ID: <CA+nmbGFpDi_Ht+wXY2P6wfUbJp7rC7SZusDFm5KWhXEoOFCgBA@mail.gmail.com>
Subject: UP0x7ec2bdda58e38d0e4eb1fd76936d40bf2c03232c87ea512808a8095f4ec33e62
To: bot@mail.unipass.id
Content-Type: multipart/alternative; boundary="00000000000057c4c905d32cdcbd"

 Unipass Test"#,
        r#"X-Mailgun-Incoming: Yes
X-Envelope-From: <proxy_s@126.com>
Received: from m151.mail.126.com (m151.mail.126.com [220.181.15.1])
 by mxa.mailgun.org with ESMTP id 61b9c596.7fb02c41f6f8-smtp-in-n03;
 Wed, 15 Dec 2021 10:38:14 -0000 (UTC)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=126.com;
	s=s110527; h=Date:From:Subject:MIME-Version:Message-ID; bh=e+QfY
	q0jEYMqC9c2dHZvJQlLyX3wypgUXNpXOKUhRlw=; b=bTZzWnxhRhPzHngXyy1s0
	DQ+SEdQSSChOCDfQ4t6SiaBZWraPVd6/c6bGLsf1OeMl1Tk4rfGEAevJDcfbgPcA
	wtq5jOktvs7F+Rm/kn1pk4kw44LTUmSHE6WRdnT5ay37JMJhBgReRKaQWa17u33C
	Vt/NeaYhq0W8vXWXlE8FAE=
Received: from proxy_s$126.com ( [124.89.119.203] ) by ajax-webmail-wmsvr1
 (Coremail) ; Wed, 15 Dec 2021 18:38:11 +0800 (CST)
X-Originating-IP: [124.89.119.203]
Date: Wed, 15 Dec 2021 18:38:11 +0800 (CST)
From: proxy_s <proxy_s@126.com>
To: bot@mail.unipass.id
Subject: UP0x573bf617a962d598a5e4c5e841453040326da68462b95091bb598d61da763211
X-Priority: 3
X-Mailer: Coremail Webmail Server Version XT5.0.13 build 20210622(1d4788a8)
 Copyright (c) 2002-2021 www.mailtech.cn 126com
X-CM-CTRLDATA: ZN4VZWZvb3Rlcl9odG09MTE0OjU2
Content-Type: multipart/alternative; 
	boundary="----=_Part_57114_1689473154.1639564691352"
MIME-Version: 1.0
Message-ID: <1e4fc897.3d5f.17dbdabc799.Coremail.proxy_s@126.com>
X-Coremail-Locale: zh_CN
X-CM-TRANSID:AcqowAC3HXGUxblhJUgFAA--.48235W
X-CM-SenderInfo: xsur55lbv6ij2wof0z/1tbiohtqN1x5ge0KVwABsx
X-Coremail-Antispam: 1U5529EdanIXcx71UUUUU7vcSsGvfC2KfnxnUU==

 Unipass Test"#,
    ];

    let mut all_email_public_inputs = vec![];
    let mut all_email_private_inputs = vec![];
    for email_bytes in emails {
        // let email_bytes = std::fs::read(dir.unwrap().path()).unwrap();
        let (email_public_inputs, email_private_inputs) =
            parse_email(email_bytes.as_bytes(), from_pepper.to_vec()).unwrap();

        all_email_public_inputs.push(email_public_inputs);
        all_email_private_inputs.push(email_private_inputs);
    }
    println!("----------------------------------------------------------------");
    println!("Test circuit 2048triple");

    let circuit =
        Email2048TripleCircuitInput::new(all_email_private_inputs[0..3].to_vec()).unwrap();
    println!("[main] circuit construct finish");

    let mut sha256_input: Vec<u8> = vec![];
    for (i, (email_public_inputs, email_private_inputs)) in all_email_public_inputs[0..3]
        .iter()
        .zip(&all_email_private_inputs[0..3])
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

        println!("r: {}", to_0x_hex(&r));

        println!(
            "email_header_pub_matches: {}",
            to_0x_hex(&circuit.email_header_pub_matches[i])
        );
        sha256_input.extend(sha2::Sha256::digest(&r.to_vec()));
        sha256_input.extend(sha2::Sha256::digest(&circuit.email_header_pub_matches[i]).to_vec());
        sha256_input.extend((padding_len(header_len) as u16 / 64).to_be_bytes());
        sha256_input.extend((padding_len(addr_len + 32) as u16 / 64).to_be_bytes());
    }

    println!("sha256_input: {}", to_0x_hex(&sha256_input));

    let mut expected_public_input = sha2::Sha256::digest(&sha256_input).to_vec();
    expected_public_input[0] = expected_public_input[0] & 0x1f;
    println!(
        "expected_public_input: {}",
        to_0x_hex(&expected_public_input)
    );
    let expected_public_input = vec![Fr::from_be_bytes_mod_order(&expected_public_input)];

    let mut cs = circuit.synthesize();
    println!("[main] synthesize finish");

    let public_input = cs.compute_public_input();
    println!("cs.size() {}", cs.size());

    if expected_public_input != public_input {
        panic!("Public input error")
    }

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
        // store_prover_key(pk_2048.as_ref().clone().unwrap(), "email_2048.pk").unwrap();
    }

    println!("[main] compute_prover_key...done");
    let mut prover =
        Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(pk_2048.as_ref().unwrap().clone());
    println!("prover.domain_size() {}", prover.domain_size());

    println!("[main] init_comms...");
    if verifier_comms_2048.is_none() {
        verifier_comms_2048 = Some(prover.init_comms(&pckey));

        store_verifier_comms(
            verifier_comms_2048.as_ref().clone().unwrap(),
            "email_2048triple.vc",
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
    let contract_inputs = ContractTripleInput::new(
        all_email_public_inputs
            .iter()
            .map(|a| a.header_hash.clone())
            .collect(),
        all_email_public_inputs
            .iter()
            .map(|a| a.from_hash.clone())
            .collect(),
        circuit.email_header_pub_matches,
        all_email_private_inputs
            .iter()
            .map(|a| a.email_header.len() as u32)
            .collect(),
        circuit.from_left_indexes,
        circuit.from_lens,
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
            "test_data/inputs_2048triple/tri_{}.json",
            to_0x_hex(&all_email_public_inputs[0].header_hash)
        ))
        .unwrap();
    file.write(&serde_json::to_vec_pretty(&contract_inputs).unwrap())
        .unwrap();
    file.flush().unwrap();
}
