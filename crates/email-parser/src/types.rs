use serde::{de, Deserialize, Serialize, Serializer};
use sha2::{digest::Update, Digest, Sha256};

use crate::error::ParserError;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DkimParams {
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub email_header: Vec<u8>,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub dkim_sig: Vec<u8>,
    pub from: String,
    pub from_index: usize,
    pub from_left_index: usize,
    pub from_right_index: usize,
    pub subject_index: usize,
    pub subject_right_index: usize,
    pub subject: Vec<u8>,
    pub dkim_header_index: usize,
    pub selector_index: usize,
    pub selector_right_index: usize,
    pub sdid_index: usize,
    pub sdid_right_index: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateInputs {
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub email_header: Vec<u8>,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub from_pepper: Vec<u8>,
    pub from_index: usize,
    pub from_left_index: usize,
    pub from_right_index: usize,
    pub subject_index: usize,
    pub subject_right_index: usize,
    pub dkim_header_index: usize,
    pub selector_index: usize,
    pub selector_right_index: usize,
    pub sdid_index: usize,
    pub sdid_right_index: usize,
}

impl PrivateInputs {
    pub fn from_params(params: DkimParams, from_pepper: Vec<u8>) -> PrivateInputs {
        PrivateInputs {
            email_header: params.email_header,
            from_pepper,
            from_index: params.from_index,
            from_left_index: params.from_left_index,
            from_right_index: params.from_right_index,
            subject_index: params.subject_index,
            subject_right_index: params.subject_right_index,
            dkim_header_index: params.dkim_header_index,
            selector_index: params.selector_index,
            selector_right_index: params.selector_right_index,
            sdid_index: params.sdid_index,
            sdid_right_index: params.sdid_right_index,
        }
    }

    pub fn to_public(&self) -> Result<PublicInputs, ParserError> {
        let header_hash = Sha256::digest(&self.email_header).to_vec();
        let from_hash = {
            let hasher = Sha256::default();
            let hasher = hasher
                .chain(
                    &self.email_header
                        [self.from_left_index..self.from_right_index + 1],
                )
                .chain(&self.from_pepper);

            hasher.finalize().to_vec()
        };
        Ok(PublicInputs {
            header_hash,
            from_hash,
            subject: String::from_utf8(
                self.email_header
                    [self.subject_index + 8..self.subject_right_index]
                    .to_vec(),
            )?,
            selector: String::from_utf8(
                self.email_header[self.selector_index..self.selector_right_index]
                    .to_vec(),
            )?,
            sdid: String::from_utf8(
                self.email_header[self.sdid_index..self.sdid_right_index]
                    .to_vec(),
            )?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicInputs {
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub header_hash: Vec<u8>,
    #[serde(
        deserialize_with = "deserialize_hex_string",
        serialize_with = "serialize_hex_string"
    )]
    pub from_hash: Vec<u8>,
    pub subject: String,
    pub selector: String,
    pub sdid: String,
}

pub fn deserialize_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: String = de::Deserialize::deserialize(deserializer)?;
    hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| de::Error::custom(format!("deserialize call failed:{:?}", e)))
}

pub fn serialize_hex_string<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut s = String::from("0x");
    s += &hex::encode(v);
    serializer.serialize_str(&s)
}
