use std::time::Instant;

use plonk::ark_bn254::{Bn254, Fr};
use plonk::ark_serialize::Write;
use plonk::ark_std::test_rng;
use plonk::Field;

use email_parser::parser::parse_email;
use plonk::{prover::Prover, verifier::Verifier, GeneralEvaluationDomain};
use prover::circuit::circuit_2048_triple::Email2048TripleCircuitInput;
use prover::parameters::{prepare_generic_params, store_verifier_comms};
use prover::types::ContractTripleInput;
use prover::utils::{bit_location, padding_len};
use prover::utils::{convert_public_inputs, to_0x_hex};
use sha2::Digest;

#[test]
fn test_2048tri() {
    let mut pk_2048 = None;
    let mut verifier_comms_2048 = None;

    // let dirs = std::fs::read_dir("test_data/emails").unwrap();
    let emails = vec![
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
    [
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
    println!("begin 2048tri circuits tests...");
    // append 32bytes pepper
    let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    let from_pepper = hex::decode(pepper).unwrap();

    let mut all_email_public_inputs = vec![];
    let mut all_email_private_inputs = vec![];
    for email_bytes in emails {
        // let email_bytes = std::fs::read(dir.unwrap().path()).unwrap();
        let (email_public_inputs, email_private_inputs) =
            parse_email(email_bytes.as_bytes(), from_pepper.to_vec()).unwrap();

        all_email_public_inputs.push(email_public_inputs);
        all_email_private_inputs.push(email_private_inputs);
    }

    let mut rng = test_rng();
    // prepare SRS
    let pckey = prepare_generic_params(2097150, &mut rng);

    println!("pckey degree: {}", pckey.max_degree);

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
        sha256_input.extend(sha2::Sha256::digest(&r));
        sha256_input.extend(sha2::Sha256::digest(&circuit.email_header_pub_matches[i]).to_vec());
        sha256_input.extend((padding_len(header_len) as u16 / 64).to_be_bytes());
        sha256_input.extend((padding_len(addr_len + 32) as u16 / 64).to_be_bytes());
    }

    println!("sha256_input: {}", to_0x_hex(&sha256_input));

    let mut expected_public_input = sha2::Sha256::digest(&sha256_input).to_vec();
    expected_public_input[0] &= 0x1f;
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

        store_verifier_comms(verifier_comms_2048.as_ref().unwrap(), "email_2048triple.vc").unwrap();
    } else {
        // if already exists, no need "init_comms"
        prover.insert_verifier_comms(verifier_comms_2048.as_ref().unwrap());
    }

    println!("[main] init_comms...done");
    println!("[main] time cost: {:?} ms", start.elapsed().as_millis()); // ms

    let prove_start = Instant::now();
    println!("[main] prove start:");
    let proof = prover.prove(&mut cs, &pckey, &mut rng).unwrap();
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
    file.write_all(&serde_json::to_vec_pretty(&contract_inputs).unwrap())
        .unwrap();
    file.flush().unwrap();
}
