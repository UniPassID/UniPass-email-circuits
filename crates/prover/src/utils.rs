use plonk::{
    ark_ec::PairingEngine,
    ark_ff::{BigInteger, PrimeField, ToBytes, Zero},
    ark_poly_commit::kzg10::Commitment,
    proof::Proof,
    Domain,
};

pub fn to_0x_hex<T>(data: T) -> String
where
    T: AsRef<[u8]>,
{
    let mut res = String::from("0x");
    res += &hex::encode(data);
    res
}

pub fn from_0x_hex(input: &str) -> anyhow::Result<Vec<u8>> {
    Ok(hex::decode(input.trim_start_matches("0x"))?)
}

pub fn padding_bytes(input_bytes: &[u8]) -> Vec<u8> {
    let mut input_bytes_padding = input_bytes.to_vec();
    let input_remainder = (input_bytes.len() * 8) % 512;

    log::trace!(
        "input_bytes len: {}, input_remainder: {}",
        input_bytes.len(),
        input_remainder
    );
    let padding_count = if input_remainder < 448 {
        (448 - input_remainder) / 8
    } else if input_remainder >= 448 {
        (448 + 512 - input_remainder) / 8
    } else {
        64
    };

    log::trace!("padding_count: {}", padding_count);

    input_bytes_padding.push(1u8 << 7);
    for _ in 0..padding_count - 1 {
        input_bytes_padding.push(0u8);
    }

    let input_bits_len = ((input_bytes.len() * 8) as u64).to_be_bytes();

    log::trace!("input_bits_len: {}", input_bits_len.len());

    for e in input_bits_len {
        input_bytes_padding.push(e);
    }

    return input_bytes_padding;
}

pub fn convert_public_inputs<F: PrimeField>(public_input: &[F]) -> Vec<String> {
    let mut res = vec![];
    for e in public_input {
        let mut e_hex = String::from("0x");
        let a = e.into_repr();
        let mut pre = true;
        for (i, v) in a.to_bytes_be().iter().enumerate() {
            if *v == 0 && pre == true {
                if i == 31 {
                    e_hex.push('0');
                }
            } else {
                if pre == true {
                    e_hex.push_str(&format!("{:x}", *v));
                } else {
                    e_hex.push_str(&format!("{:02x}", *v));
                }
                pre = false;
            }
        }

        res.push(e_hex);
    }

    res
}

pub fn convert_vk_data<F: PrimeField, D: Domain<F>, E: PairingEngine>(
    domain: D,
    verifier_comms: &Vec<Commitment<E>>,
    g2x: E::G2Affine,
) -> Vec<String> {
    let mut vk_data = vec![];
    // omega
    let omega = domain.generator();
    let mut x = [0u8; 32];
    let _ = omega.into_repr().to_bytes_be().write(&mut x[..]);
    vk_data.push(to_0x_hex(x));

    // vk
    for c in verifier_comms {
        let tmp = c.0;
        let mut bytes = [0u8; 64];
        let _ = tmp.write(bytes.as_mut());
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[32 - j - 1] = bytes[j];
        }
        let mut y = [0u8; 32];
        for j in 32..64 {
            y[64 - j - 1] = bytes[j];
        }
        if tmp.is_zero() {
            vk_data.push(to_0x_hex(x));
            vk_data.push(to_0x_hex(x));
        } else {
            vk_data.push(to_0x_hex(x));
            vk_data.push(to_0x_hex(y));
        }
    }

    // g2x
    let mut bytes = [0u8; 128];
    let _ = g2x.write(bytes.as_mut());
    let mut xc0 = [0u8; 32];
    for j in 0..32 {
        xc0[32 - j - 1] = bytes[j];
    }
    let mut xc1 = [0u8; 32];
    for j in 32..64 {
        xc1[64 - j - 1] = bytes[j];
    }
    let mut yc0 = [0u8; 32];
    for j in 64..96 {
        yc0[96 - j - 1] = bytes[j];
    }
    let mut yc1 = [0u8; 32];
    for j in 96..128 {
        yc1[128 - j - 1] = bytes[j];
    }

    vk_data.push(to_0x_hex(xc0));
    vk_data.push(to_0x_hex(xc1));
    vk_data.push(to_0x_hex(yc0));
    vk_data.push(to_0x_hex(yc1));

    vk_data
}

pub fn convert_proof<F: PrimeField, E: PairingEngine>(proof: &Proof<F, E>) -> Vec<String> {
    let mut proof_data = vec![];

    // proof
    for c in &proof.commitments1 {
        let tmp = c.0;
        let mut bytes = [0u8; 64];
        let _ = tmp.write(bytes.as_mut());
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[32 - j - 1] = bytes[j];
        }
        let mut y = [0u8; 32];
        for j in 32..64 {
            y[64 - j - 1] = bytes[j];
        }
        if tmp.is_zero() {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(x));
        } else {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(y));
        }
    }

    let tmp = proof.commitment2.0;
    let mut bytes = [0u8; 64];
    let _ = tmp.write(bytes.as_mut());
    let mut x = [0u8; 32];
    for j in 0..32 {
        x[32 - j - 1] = bytes[j];
    }
    let mut y = [0u8; 32];
    for j in 32..64 {
        y[64 - j - 1] = bytes[j];
    }
    if tmp.is_zero() {
        proof_data.push(to_0x_hex(x));
        proof_data.push(to_0x_hex(x));
    } else {
        proof_data.push(to_0x_hex(x));
        proof_data.push(to_0x_hex(y));
    }

    for c in &proof.commitments3 {
        let tmp = c.0;
        let mut bytes = [0u8; 64];
        let _ = tmp.write(bytes.as_mut());
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[32 - j - 1] = bytes[j];
        }
        let mut y = [0u8; 32];
        for j in 32..64 {
            y[64 - j - 1] = bytes[j];
        }
        if tmp.is_zero() {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(x));
        } else {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(y));
        }
    }
    for c in &proof.commitments4 {
        let tmp = c.0;
        let mut bytes = [0u8; 64];
        let _ = tmp.write(bytes.as_mut());
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[32 - j - 1] = bytes[j];
        }
        let mut y = [0u8; 32];
        for j in 32..64 {
            y[64 - j - 1] = bytes[j];
        }
        if tmp.is_zero() {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(x));
        } else {
            proof_data.push(to_0x_hex(x));
            proof_data.push(to_0x_hex(y));
        }
    }
    let mut buf = [0u8; 32];
    for e in &proof.evaluations {
        let _ = e.into_repr().to_bytes_be().write(&mut buf[..]);
        proof_data.push(to_0x_hex(buf));
    }
    for e in &proof.evaluations_alt_point {
        let _ = e.into_repr().to_bytes_be().write(&mut buf[..]);
        proof_data.push(to_0x_hex(buf));
    }

    let tmp = proof.Wz_pi.0;
    let mut bytes = [0u8; 64];
    let _ = tmp.write(bytes.as_mut());
    let mut x = [0u8; 32];
    for j in 0..32 {
        x[32 - j - 1] = bytes[j];
    }
    let mut y = [0u8; 32];
    for j in 32..64 {
        y[64 - j - 1] = bytes[j];
    }
    if tmp.is_zero() {
        proof_data.push(to_0x_hex(x));
        proof_data.push(to_0x_hex(x));
    } else {
        proof_data.push(to_0x_hex(x));
        proof_data.push(to_0x_hex(y));
    }

    let tmp = proof.Wzw_pi.0;
    let mut bytes = [0u8; 64];
    let _ = tmp.write(bytes.as_mut());
    let mut x = [0u8; 32];
    for j in 0..32 {
        x[32 - j - 1] = bytes[j];
    }
    let mut y = [0u8; 32];
    for j in 32..64 {
        y[64 - j - 1] = bytes[j];
    }
    if tmp.is_zero() {
        proof_data.push(to_0x_hex(x));
        proof_data.push(to_0x_hex(x));
    } else {
        proof_data.push(to_0x_hex(x));
        proof_data.push(to_0x_hex(y));
    }
    proof_data
}
