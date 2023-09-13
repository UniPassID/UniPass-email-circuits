use std::time::Instant;

use crate::{
    circuit::{
        base64::{base64url_encode_gadget, BASE64URL_ENCODE_CHARS},
        circuit_1024::Email1024CircuitInput,
        circuit_2048::Email2048CircuitInput,
        circuit_2048_triple::Email2048TripleCircuitInput,
        openid::{
            OpenIdCircuit, SUB_MAX_LEN, HEADER_BASE64_MAX_LEN, ID_TOKEN_MAX_LEN,
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
    println!("pckey.max_degree {}", pckey.max_degree);
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
X-Envelope-From: <Hello.Stitch@outlook.com>
Received: from JPN01-OS0-obe.outbound.protection.outlook.com (Unknown [40.92.98.57])
 by mxa.mailgun.org with ESMTP id 61cd7863.7fd77879fb30-smtp-in-n02;
 Thu, 30 Dec 2021 09:14:11 -0000 (UTC)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Tcnuwk6fRNZm00Pd7bxDBZzR86s3EdfuejXE3MNtak7xhe1iwP+gtqafeAFTcKOfO7R5dqC3JAoUQK2gyXDaEXrdP1tOJQ/ucY4KqHHiuKzNndwEwMW3ynD5UA4ljV7l8/J5/xszaw+F9iSj60h7lE5MFeAq+wSQvEy5+waRnBh9wliD899PqN1erb8So5LlqUppWL6AoBbzF+T8ER7i9XRDqbBXMnAqU+S5n4TGOIYZLQey65XoA6kNUMDK+6u7NKBDjKf+5CiEspZrY7uvKq7+XOoPUKINZXElWXd3Ma3UJFDh2xfURRFvCN/XUD5Fq76lhSgDpN9TCphW0fehhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=58Y8lwiSFAd1tp/r+jLyxa+DLmKP46VvLdLK7MdQV/w=;
 b=mr0mH/NesKz6ROPwCLLLnxe0yn7XQGszuV/0ykANt1ef951FYwNK0Mu8qzB5G2NNeZPnyufWg4KFE2PXnCj7mpKdPJ3664wdsB6eYY9bcsgKLvDj7nVYbZd8h3WnjQGHbBK4kRTx057ASWwiHhc3ZwLzUeNZY5+vnIgO4BHoFqxZN/xlNnLLgfrbyXtQZJU37TUbLctTo9U1u9NyYKzXAN2Dj5p9+CcKstqzM3ywlH+j7gfWKzI0SG6kkqdKdtb8ntb6sCCI9ja5chkttHOmTWlExdpwyfDEj1ApahZeERu7r/RFIznXtrnYJEuQUiV3YEGUt7KUFjPI/NgglqHuFg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=outlook.com;
 s=selector1;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=58Y8lwiSFAd1tp/r+jLyxa+DLmKP46VvLdLK7MdQV/w=;
 b=mHbqekOajLtVtt5DX9Qhac5veDXYAsSjGk4n3JMpaGS8PtBNh6uONDxE+STA7GbCGme/VucWhLKHkwalEtS7B9H963N0AanIdpLYq0m//LGCRSdH/nfjpOSyjg5x7IK0MHLA6fEOgw2xlFDW5fPKGruBcyVh0cOZQmEqX430/QoWphZ7RXtGsGBfNCybY0pRYEdJ1kMZ06L/iyp6vWOJO4ccZgnubLgm0PCoixAcqFMmoESGNEzkqSrANv2wKXd6vsEUFJYxvbEqERHg2H97QLlRpeHEhvx/k+E0TdPG4gzDDLVJACaN908TabBNG40sGHT1yROdY1IKnlRZhEl6MQ==
Received: from OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM (2603:1096:604:18a::6)
 by OS3P286MB2152.JPNP286.PROD.OUTLOOK.COM (2603:1096:604:197::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4823.19; Thu, 30 Dec
 2021 09:14:09 +0000
Received: from OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
 ([fe80::3cc9:dd42:cf91:fef0]) by OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
 ([fe80::3cc9:dd42:cf91:fef0%7]) with mapi id 15.20.4823.024; Thu, 30 Dec 2021
 09:14:09 +0000
From: crypto stitch <Hello.Stitch@outlook.com>
To: "bot@mail.unipass.id" <bot@mail.unipass.id>
Subject: UP0x7b57b9e291a11f2fb83bf7e75d50f476c1a2ade7c326a92166f4c7816718692b
Thread-Topic:
 UP0x7b57b9e291a11f2fb83bf7e75d50f476c1a2ade7c326a92166f4c7816718692b
Thread-Index: AQHX/V2a95slKZc450SjvGFDlhV3OQ==
Date: Thu, 30 Dec 2021 09:14:09 +0000
Message-ID:
 <OSZP286MB22213FC93314A3D4C328FB2ADD459@OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM>
Accept-Language: zh-CN, en-US, ar-AE, ja-JP, en-CA
Content-Language: zh-CN
X-MS-Has-Attach:
X-MS-TNEF-Correlator:
suggested_attachment_session_id: 6a3827a1-d4ea-3b84-8290-d085d8c8b4ab
x-ms-exchange-messagesentrepresentingtype: 1
x-tmn: [SkuKVqBrdKsdaTs3MpTFheDglqyuDp+l]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: e219aded-3dcb-44ae-6e40-08d9cb74bcc0
x-ms-traffictypediagnostic: OS3P286MB2152:EE_
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info:
 OP9l+BXgWdFwVPL4S4YBxfp91krykLvoCZw4fOMJbAtvm/3YVd473cDh1X4JdUtfZaMR8RQUA4I5NB+VKp05UrfMh96//MKAqk3/KNfWkUdFgB3vMH/QjDrhknyvKEkZSlmVIYIKZP5ZiXCmWqUETzjnSWNz6Y/IZU3wEasOAPrqf/+awNOFmc9AOTtijlSHTkj0tLO/4M0QfiV6Cq//K4kkO5FuMQoWshOEnAT2zQjC1OSvQ3itCznn+lIjFkQfYEqTqWh01HclIvlLnpYI9XgkzE9cRA6hkOj+hFTXqY8CdhOC4/za2eBVKNOOAt5X3rEFqVjCuTxKZDbqHiHP5ZJCRr0qAIQgsNBDFfHtU0RBb7NZPW/2WXDf6qVye8A/H0phEwTtEPgELiCGiS/ZC1+8zrxVtHUp0VG8GJ1anEGn28yDGeybijfK7Fgn4lE73dcGxcE95ts0Y3rEkzbvYzWanUB0y/xamqUqpb2NSjXLR6cHnKo/PoaAajSSj8SbPULULRbfiVv9L89Xmnl1iMk4vt9LjvVx/r7+q1EnfYEXTteD8x8171YdY60CVw2lmDVqi2pfTOvTHLmk8GcU5g==
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0:
 kooMZugDeYXyp/stHuKY4LQk9VsipTTdPSKW8+n4KB5SvJp/Vo8bTTH6xIAJIlngo0r9ARgMRCEDy1s+8keAfbxBENDaSKhT8aRDet2zrPAkjca+BzCDUamMBKS/9eXbrHrVH7gKrseR24aWutUBYdhCeXCWan2CxtQYnUZJzRCZ+h+xcGOfxDsfsC1fU2Se+UaIXrwfKcBckNrWigapMI6qiOkYDd0AUCDzRoQssVj6/5HCuldLwHkRAJuo8SxaaL+EO4HR470i3EYz4PUIpXv2uMyyEDRiTbL6lF7ubNtl8hM0XgB3XyLdK4bbzfkIuLNzraZGX1MGIRIBaNR7DobbmmRwETZpgYVkjynvdHS7lUnIdE4V+NBpa2Ug2spL/QtsxV/1w5i+Uf6/qoffGTWFOG1IHfFXEKftCK2htXifSakPfakmxXOkjQBb81dnRySlDJzIdhixMKLgN3vFX/mhkIpsLVsJmy5IQZujw7QW318+hxPjue5NyEsl1rpHSGn9Rczywh7VRJyR/OasR7o+urTQ87a1S0kkN1+9q4ocntO0h5BysXJLBg0yilWHNSi4MHdkHOlTttYxVJ6HNfzHUybuAuogzSukboCeyr8WuXk817FgLWzKJOyPxencbe7/2d33BD7bst5VOTFB4cqtV5P3QLXraGgrJl4gjnzEr9hDSPQrZ8aNM1aqrIrZFO5MvEMdP3vZcL/ON7SvNe4pce9RZnSOStjmcCOrVZxQWoK6sStARK1hp44W2aLqB5Fw7Ww8ve1qDbVWVgta26NjQTLbqZvgXKSKSOT6JQE398AUmKGc8Kg6zsAqyoPFKtfXxtFINytak2/1GuQypHKudqYZs65lr8vo6YKianQoiHl6uzTV0fiKjc1hwYP3ybdBRUwt/DJ/AomEaw0nwb+NsqEXZ7HnEziCfbMtpJKkD+x+H3thHItNnmJho15R
Content-Type: multipart/alternative;
	boundary="_000_OSZP286MB22213FC93314A3D4C328FB2ADD459OSZP286MB2221JPNP_"
MIME-Version: 1.0
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: e219aded-3dcb-44ae-6e40-08d9cb74bcc0
X-MS-Exchange-CrossTenant-originalarrivaltime: 30 Dec 2021 09:14:09.2082
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: OS3P286MB2152

 Unipass Test"#,
    r#"X-Mailgun-Incoming: Yes
X-Envelope-From: <HEYStitch@outlook.com>
Received: from JPN01-OS0-obe.outbound.protection.outlook.com (Unknown [40.92.98.95])
 by mxa.mailgun.org with ESMTP id 61cd7831.7fb9bcb8ca80-smtp-in-n01;
 Thu, 30 Dec 2021 09:13:21 -0000 (UTC)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=bvAXH2s/KUoVAEsxor19K37aze2+REbo/ggS9Cdxj7c9slelXc+qV2Dl970uYvZjVAqBF0DbwDJ5T+spR0Ib00PtXUlWK46pfZI9Q24gbvjgcolpvfasg2n+VZLa4yhOacBUvx8nD53Ve0CtFs8OTb0HbJFBd6oQx3lMYbN81tNoAka9nE5iCT1hEQ10/0VHGLuavRAD0bmjDyUztliHNNHyDoabg3gZ+T0QD1wJ+AcFfp+rjf1LJ7Duim0QT160QWZapfqk4QYjV0thn7AxbYUciiAe54uB02Jpw4rgdgWDDRbMEAthbQ+7++0g1cXNf8vt3bxmwodmp4/gjC6SSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=tpotk81iP/Mjyq2iZOznb1AUM7rl1nqr/ZyialOIlKg=;
 b=OwTyritpfgo6jMAT+iBEiE++cRjuHkW8+z/vqysNy8xLUxd9+X6qC9x07uoUPQIc7Uu0JZPhV3l1zzvJmTo4fWQNcsVa23gfhrnpj/llV8vLpmQxtZfUgCyV2Xwhwt988Ba0ja+1cviMDYZBOCoPc9iymdTKWcBOKjwgvPRy7u8Lc31EqUmC0IWaIEKijEyGC5FwJmUh3lW9MwNTDMSP6bUZVORsTGX2GJvJfZiwNTiZ3G4NJa3wQW6+QU61xOKirL5OKatm8dTh/mLZEtOR3tesR0iO55l6HXzn8PmMMfOfaugktAhebgMQLJMJnAtNQjYlob6IMjrlL19j3U9UwQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=outlook.com;
 s=selector1;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=tpotk81iP/Mjyq2iZOznb1AUM7rl1nqr/ZyialOIlKg=;
 b=pPuGbJKkvsiEA2M55aFhbefSr+PA+u2HxyCpfQPWmHLrdWQqo0iNJUpYBsM1vcfqvDgdVdGiG0rIImDV2NbfVDroW30KMrkJEvqMdl4WF5umxeJ//sv2ZPLF/TirgvQfwoYMofWYDNOeu88zGCjJdqjYoV4yMCkIBHth8uJJpCfdxp4ReXKYhEIBQsy/6xFUvdTygKSpQAX0Py4vPC6gbA0KRFg8Z+lYWFx+vWuzSIG9FRc2Rd8fVJ/++7aoYneTkWWB/4IeQS5H4rVXOohuS1VMZegXSmBETang8iNqn6U8zf2bXBe/gsCGof0uX58AB+VevTk90UaOKoDZRIkrDQ==
Received: from OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM (2603:1096:604:18a::6)
 by OS3P286MB2152.JPNP286.PROD.OUTLOOK.COM (2603:1096:604:197::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4823.19; Thu, 30 Dec
 2021 09:13:19 +0000
Received: from OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
 ([fe80::3cc9:dd42:cf91:fef0]) by OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
 ([fe80::3cc9:dd42:cf91:fef0%7]) with mapi id 15.20.4823.024; Thu, 30 Dec 2021
 09:13:18 +0000
From: crypto stitch <HEYStitch@outlook.com>
To: "bot@mail.unipass.id" <bot@mail.unipass.id>
Subject: UP0xd4df9a846fae616511da24cdcf959fff31c9d387fda911dbbcc3b160dc95a967
Thread-Topic:
 UP0xd4df9a846fae616511da24cdcf959fff31c9d387fda911dbbcc3b160dc95a967
Thread-Index: AQHX/V18dXu9ULYse0KWsAy4tcjfmg==
Date: Thu, 30 Dec 2021 09:13:18 +0000
Message-ID:
 <OSZP286MB22210BBFEBDB6A16BCFEF798DD459@OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM>
Accept-Language: zh-CN, en-US, ar-AE, ja-JP, en-CA
Content-Language: zh-CN
X-MS-Has-Attach:
X-MS-TNEF-Correlator:
suggested_attachment_session_id: 2dc60353-f96c-fbbf-749d-b921e615494b
x-ms-exchange-messagesentrepresentingtype: 1
x-tmn: [A7ABfCiXaBe7e/fbXl+HePmgvgM0li76]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: dc3ceccf-5dcd-4807-b342-08d9cb749eba
x-ms-traffictypediagnostic: OS3P286MB2152:EE_
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info:
 tjClpfGHQEzn4h6zMfp50mVxmj53HPk6mrCMnFR5Q6XSzz5NNh3a76rkAIPVZgm4jcvijPDPiv8p/m+yTChXzsXUXQcIS84AF+mh5Dwi5CkL61J2rs6VUt1/CValmd4hQuY2V0jzKzdp2z3pYV68uxVdcPZz9I9gguvOD7yHXoWtqWBhnz28jt+QIzzE0ctdKel6VDmrAlL7PIeKFFo8uyyXP/S7xSqpgJPfBZqEvM0T3gahxNNHC8cXEHsEMDGX2zPWcrKe4wRQKq+GdAgU1TtE1MS8FFtUf8dBW9IbeWT0GJ+QDIS9e5rcCct8zuW+M0Swxoz2OrvgjxIX41w0o9j5NIsO/3UwScoxctaZ3wiRqIabyPrkEjN1QiQbeP9LXPmJCqFfBAgGgJs3aJjKtLqIb6ZDF+/ClF/+7cuR/Mjy7H69dSNRwhGmgJnJ4v6mlY2kLGa9I9J8gMjcBTa5WsBAjVw//puVxO/js6xF60NuVC19lYPtzuzMB0ahsHRbYHlUFfUHj7HfoqmH0Xis8Ee8qSrzGaer2pr5W1mJIA2ps20YJh2rjBI9grlGrx7vX/Tu4N6z+e27PYb8CGyBdw==
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0:
 dJTr4EsNz8bQTQJYTDVRhDzfTTV9H2/PrpCXA5+ULjFotCArFIvCP2PxNSG2oUJ1ulxt9VbhVn0IBkjvgCgi7VMzhbzaBSI/pbh8kevs4FUjUVhfEXB8eZqTgr+hDBgLsET+xl63YQ75tW65r9uGD+5P28ZXzv5ikQASBbEP1NBmTCbnM5pvKGusVvWlYGlOSyQIuReW1GLNHKyfCf5gR7Z5V7aY48lnU+fVGZShC/1IxtrMg23cUgB/8ugkB+hPCnctTTGaZAVqBPXAQgwzGvRP5IWQKlEYoXtGfGRGvqAGEhDfLw2R0Vpto9hX1MeGMA/JkWLWhcPRd5KYcJz6SidQldtsoW7mCysEnART7LewzsBOHquspbdy6IpJUzPBmYyr9XnexHYidhOaLqJFGMaSbdcp82y35c6X02/F9mhJtMBexE1HW8HILjo0hk06GSc9/NpdIeQgckoVlwL79vtcC5I4+/TefGj3EFH4IkIo/QrI+/iQv7fTQPGCUkciHw/63WWdEez1MrfSl5rdAaOA2vydZt3UAwPRNMDO53BHf9fqmPAQp/eGTOhXYm/d92b9CvvHiwfSFDY/DgLuvAulTRJSmEvZsrH5LF2OgybU1XItxaUDjoxJkWAOVnAJ/jRcjn/IagNxDKaoHvNHsbOLpOYh93OB1AoDsMXhE4iBoeiWWEISJ6FEJLdBBx6+V7XBhU6ozgsyGxprNydP8meEM9XGZ15uB5VQw7Q07iqbgKNlT2ZX9SpSwAU1mO8tKYOCdBMQNx2UhBzI2odfvhIlJTbFWccUecdOoJTBCE+5BURyE+qiekbLgz4oiYq9KLmO6KTS+RxSiCZSCIMkucPHjGGdNAkch0uqS52CyOPltHybGliq6GPdCFkiGeopv734+hAriagLfTlrBCdx7iKIlbK+KNzAdqlZNBadkwFWdtFd1DtOMQIgePQkY1ub
Content-Type: multipart/alternative;
	boundary="_000_OSZP286MB22210BBFEBDB6A16BCFEF798DD459OSZP286MB2221JPNP_"
MIME-Version: 1.0
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: dc3ceccf-5dcd-4807-b342-08d9cb749eba
X-MS-Exchange-CrossTenant-originalarrivaltime: 30 Dec 2021 09:13:18.8690
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: OS3P286MB2152

 Unipass Test"#,
    r#"X-Mailgun-Incoming: Yes
X-Envelope-From: <cryptostitch@hotmail.com>
Received: from JPN01-OS0-obe.outbound.protection.outlook.com (Unknown [40.92.98.49])
 by mxa.mailgun.org with ESMTP id 61cd77f3.7fe3f008e8c8-smtp-in-n01;
 Thu, 30 Dec 2021 09:12:19 -0000 (UTC)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=lv2UhtBMOApYcQVmRXb313hT5BPQzOhf8YUMteGBp/b8dD24EKpLXbjNYTHOvJmEZIvWSEw9aruGkozUN8iauJCOoccl1kESFNgf7PTd7Ie7nHTRJ+MX0T6RyaZv/ktloGRTkOZ1Np6LCROldjJoOXQJ0KmLQMYHRArOjbCjch1G7HGmjlFqLaM8t+asLvT4LQYRwD/Jpdz0BfR2TvEtMst20EVvqrmR5muxF04luCCkjJbvP8d9af4DLbVlkHfH/g8ImagbtEdJxa+ECOqIa7Xm8Wu01nKWbIhdpdtFsE6fQicYHL2ldVdc8XOyXObtHLEQf3gTMIWiAGB1YSt9Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0jPzAQYrFyF8C/556xBRj2O7bsw1Vmrl0E0w4R6WiHo=;
 b=eCajimeNjNjxXq0lKMXuHhfGeteuIPaQAvDAV5o7rfk1sMHPpGQdVfTjSbwHi7VgBpGkWDLfHE++aamu82rUdrT7b4AAd+edBT40XN1nBE4l3w19FC7VyJ00od9TJkrLlStheod5sXJRJCNhqDtXkmIXHR5WXLqkWrURCNX6iP/50kXk8HZxKVU3sRY57Yb5zYpDGZ2dJHEkP2Ks+6ZUZb62P9ErgnBzs6Ksqn14Bc5uL1SWJi9/53o/NnuIX3x6MsDtX1LZGHm5VzUrORRYE5OUa7VwItejpH93LRg4sKQx34JctB977LH4n/5GhGBvestHbS5Rd+uM13zpiELwfQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=hotmail.com;
 s=selector1;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=0jPzAQYrFyF8C/556xBRj2O7bsw1Vmrl0E0w4R6WiHo=;
 b=HQpHpHOo3s9aQwZRVr6EfFD8/zW0SYCl8tuEPZeVf1o7hyKcVhvsYpBKqY/0IQszDuix1tsldUeqMtH9o8sx3Fyj6WDrQ+182cU4cnoj0MAhvRxREQIHHm51jAxdqLJiud73E70fWxwP2gWAeklV32EZoUlBWDtvEBqy618tss7B50EUJw1xJ/dVZRrftkwu3070dCc5q8hk27Kxv8ItizNr6FT9RqOB/2OcodX5x0ycI4uOlkxQjaYUcgtsf5FvOClr0LO7XiNuj3FhqOgAWi6mtOPshXN3ds24FsaNF8Vyok9gZVPc+LKtMfDZ5kqkmtbYLh9m+16DseCbwDONBg==
Received: from OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM (2603:1096:604:18a::6)
 by OS3P286MB2152.JPNP286.PROD.OUTLOOK.COM (2603:1096:604:197::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4823.19; Thu, 30 Dec
 2021 09:12:16 +0000
Received: from OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
 ([fe80::3cc9:dd42:cf91:fef0]) by OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
 ([fe80::3cc9:dd42:cf91:fef0%7]) with mapi id 15.20.4823.024; Thu, 30 Dec 2021
 09:12:16 +0000
From: crypto stitch <cryptostitch@hotmail.com>
To: "bot@mail.unipass.id" <bot@mail.unipass.id>
Subject: UP0x48549a127ae5e19a8205e11b7af6667eb4210917d564f16db10b00ba750489ec
Thread-Topic:
 UP0x48549a127ae5e19a8205e11b7af6667eb4210917d564f16db10b00ba750489ec
Thread-Index: AQHX/V1Xp/DYBmgpLEyWTQdf8SeSkQ==
Date: Thu, 30 Dec 2021 09:12:16 +0000
Message-ID:
 <OSZP286MB222191BDFEE731C608AD735DDD459@OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM>
Accept-Language: zh-CN, en-US, ar-AE, ja-JP, en-CA
Content-Language: zh-CN
X-MS-Has-Attach:
X-MS-TNEF-Correlator:
suggested_attachment_session_id: 4f5e4f69-4708-6081-1dbc-1dd8d220f5aa
x-ms-exchange-messagesentrepresentingtype: 1
x-tmn: [IDA6Gt6C0VDJqEBH7BlksQozqEnf3UDW]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: af6c1643-d64b-4209-4f6f-08d9cb7479a5
x-ms-traffictypediagnostic: OS3P286MB2152:EE_
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info:
 vGQCQN8Du/PP0XTtU1qRJTR3F5TqUDu4a7gkRBfLd3qqfZBDLkebJVI+wTvya+0HhHhJSTPWDm5PpWnG3PNm3oAEcL9yyVwDTLqKoUlRkQNP3NXYxaXQGttLef+7morNt0yHYmTJBZuRtoiUjpEF3USsflUZR7+9JejFP3xkUF+bOqYzsK0P/VWmajjfR/164y6V4t5Hgyd2CywmjSplPoxdu+BO7XOCSO1ies9W986ViT/hmMd5O0DFteyXrVgL6N32Dw8wwDjkPAZNIvSdQ5QlliQeHW+tpBzqA7j0/uVBcWxlJrQ8rGQDgjKreAz6kXq99C44D27D/BJNU7nB2hZWS0wU3EoyJNE3GVqdif4iyrgUrI5W8Zi4CoIpKerJfJSyfkgA8dpYkMk9CLIgQoc7GvHTda1vXoSLbCz22zA8qxo0YXGX0xjtniSzeoKwwCEvzBBOHDPiKLi+Er4FxIDXkokSDNYb40cGG7OS2s5c5wj69uGZCuYKPckgVa5g7TALWOrohaixRBxrvaLI7NIvhgO0tjHb7dlOKLirsHJp+VzN5Ou/nyhNrGg8tmBwEV3/Hz0izJfbFZ1EvRBgVA==
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0:
 D8yVZpQpeTW9PCjcnc2mPH1hWziqpEBvd7jNwovRqHccB8jna/PLDOUIJH+hT+Gk+O7BGLOqeoGp3SuODwDpXEl5Okz+QySw5Fncewr6LjitiSibA321351rCouRKa+8sLolNLDmi9yBMZWzv3Fus1/4ETE5exw6RDRXNkZSSwN8ZkNqgd8sA1y8seOLIjeNp2ZzQR62OX4ISxbQx3lh7iagSP+gMNT28F5Tc5q9cHhBPzK3LGhY/tAAEBDBuNZH8ZgzZwdEdQZKuCCqxZ3g8GwTctSTBjOTvw2IvmR0jux+SghfYOO1gWpv6pHlsv21I+LNVPAxqRUYiLBoeBh7XiJ491y8OQNwUCVjoWMSVp1rS83jb8ArczZ6O+InV8exor4b9tPwzxW9ePYUTHtpueyHED+RHAR9XPG2PwBCaBMSH/re4+SKWwp6YrDZjzN/y2stB/6J5Y6lxgwysJJOm+/s1LQ8SwsQko0l6+9c5GFnNxFFXbk86jwTTCMVJdiPDATUGpNxw/TduPhS2khv14G24Yj6/0a3lBLvgWn8y4EXJhpI+F/ezcDgpHCv7+zxqPJnMxzn9kzkuBgDMTzLhXWgrRYP+BcPVXrAkB49gtILwsaUZ2XSUY29OzClKqA31KoVlAyt97Xx8VnXvkClfdTojtLdOPHn1VFUy4sYU2btOviBC51d/jaY3IAn5aaOwivN/cfqO5rFyHi++Z2qDg4tm6ntSratIRrW2BU5wH3zcG2MdUFcw7wPrwLBlgN9HnJsaSBzlUQd7zMILNl14mwBNeIWyhlNzITeS0MH64ytQUopkAEdzDwSZCbkRts+sQALUQ8Iuby8KxpTcqapG/LHSuwNYJuoTSpSMQIjA8CEy7r7rmS/RAbytNK3BVPEIYDB4ByGYKzmfP4I3KgS/719SH8+VMjPNQw/iam4hXK3Qu03b2xSZMM/Bo6aR8pG
Content-Type: multipart/alternative;
	boundary="_000_OSZP286MB222191BDFEE731C608AD735DDD459OSZP286MB2221JPNP_"
MIME-Version: 1.0
X-OriginatorOrg: sct-15-20-4755-11-msonline-outlook-05f45.templateTenant
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: OSZP286MB2221.JPNP286.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: af6c1643-d64b-4209-4f6f-08d9cb7479a5
X-MS-Exchange-CrossTenant-originalarrivaltime: 30 Dec 2021 09:12:16.6688
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: OS3P286MB2152

 Unipass Test"#,
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
        public_input[0] &= 0x1f;
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
        public_input[0] &= 0x1f;
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
        Email2048TripleCircuitInput::new(all_email_private_inputs[0..3].to_vec()).unwrap();

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
        sha256_input.extend(sha2::Sha256::digest(&r));
        sha256_input.extend(sha2::Sha256::digest(&circuit.email_header_pub_matches[i]).to_vec());
        sha256_input.extend((padding_len(header_len) as u16 / 64).to_be_bytes());
        sha256_input.extend((padding_len(addr_len + 32) as u16 / 64).to_be_bytes());
    }

    let mut public_input = sha2::Sha256::digest(&sha256_input).to_vec();
    public_input[0] &= 0x1f;
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
        let sub_peper_hash = sha2::Sha256::digest(&circuit.sub_pepper_bytes).to_vec();

        let mut hash_inputs = vec![];
        hash_inputs.extend(idtoken_hash);
        hash_inputs.extend(sub_peper_hash);
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
        let (location_payload_raw, location_sub) = bit_location(
            circuit.addr_left_index,
            circuit.addr_len,
            PAYLOAD_RAW_MAX_LEN as u32,
            SUB_MAX_LEN as u32,
        );

        hash_inputs.extend(location_id_token_1);
        hash_inputs.extend(location_payload_base64);
        hash_inputs.extend(location_id_token_2);
        hash_inputs.extend(location_header_base64);
        hash_inputs.extend(location_payload_raw);
        hash_inputs.extend(location_sub);

        let mut public_input = sha2::Sha256::digest(&hash_inputs).to_vec();
        public_input[0] &= 0x1f;

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
    output
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
    println!("pckey.max_degree {}", pckey.max_degree);
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
