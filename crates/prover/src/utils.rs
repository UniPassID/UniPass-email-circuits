use ark_ff::{BigInteger, PrimeField};
use serde::{de, Serializer};

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

    println!(
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

    println!("padding_count: {}", padding_count);

    input_bytes_padding.push(1u8 << 7);
    for _ in 0..padding_count - 1 {
        input_bytes_padding.push(0u8);
    }

    let input_bits_len = ((input_bytes.len() * 8) as u64).to_be_bytes();

    println!("input_bits_len: {}", input_bits_len.len());

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

pub fn deserialize_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: String = de::Deserialize::deserialize(deserializer)?;
    Ok(hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| de::Error::custom(format!("deserialize call failed:{:?}", e)))?)
}

pub fn serialize_hex_string<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut s = String::from("0x");
    s += &hex::encode(v);
    serializer.serialize_str(&s)
}
