use email_rs::{dkim, Email, Header};

use crate::{
    error::ParserError,
    types::{PrivateInputs, PublicInputs},
    ParserResult,
};

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_header(
    dkim_msg: &[u8],
    dkim_header: &Header,
    from_pepper: Vec<u8>,
    from: String,
) -> ParserResult<(PublicInputs, PrivateInputs)> {
    let from_index = match find_subsequence(dkim_msg, b"from:") {
        Some(index) => index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let from_end_index = match find_subsequence(&dkim_msg[from_index..], b"\r\n") {
        Some(index) => index + from_index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let from_left_index =
        match find_subsequence(&dkim_msg[from_index..], format!("<{}>", from).as_bytes()) {
            Some(index) => {
                if index < from_end_index {
                    from_index + index + 1
                } else {
                    match find_subsequence(dkim_msg, from.as_bytes()) {
                        Some(index) => index,
                        None => return Err(ParserError::HeaderFormatError),
                    }
                }
            }
            None => match find_subsequence(dkim_msg, from.as_bytes()) {
                Some(index) => index,
                None => return Err(ParserError::HeaderFormatError),
            },
        };

    let from_right_index = from_left_index + from.len() - 1;

    let subject_index = match find_subsequence(dkim_msg, b"subject:") {
        Some(index) => index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let subject_right_index = match find_subsequence(&dkim_msg[subject_index..], b"\r\n") {
        Some(index) => subject_index + index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let dkim_header_index = match find_subsequence(dkim_msg, b"dkim-signature:") {
        Some(index) => index,
        None => return Err(ParserError::HeaderFormatError),
    };

    let sdid_index = {
        let d_index = match find_subsequence(&dkim_msg[dkim_header_index..], b"d=") {
            Some(index) => dkim_header_index + index,
            None => return Err(ParserError::HeaderFormatError),
        };

        match find_subsequence(&dkim_msg[d_index..], dkim_header.sdid.as_bytes()) {
            Some(index) => d_index + index,
            None => return Err(ParserError::HeaderFormatError),
        }
    };

    let sdid_right_index = sdid_index + dkim_header.sdid.len();

    let selector_index = {
        let s_index = match find_subsequence(&dkim_msg[dkim_header_index..], b"s=") {
            Some(index) => dkim_header_index + index,
            None => return Err(ParserError::HeaderFormatError),
        };

        match find_subsequence(&dkim_msg[s_index..], dkim_header.selector.as_bytes()) {
            Some(index) => s_index + index,
            None => return Err(ParserError::HeaderFormatError),
        }
    };

    let selector_right_index = selector_index + dkim_header.selector.len();

    let private_input = PrivateInputs {
        email_header: dkim_msg.to_vec(),
        from_pepper,
        from_index,
        from_left_index,
        from_right_index,
        subject_index,
        subject_right_index,
        dkim_header_index,
        selector_index,
        selector_right_index,
        sdid_index,
        sdid_right_index,
    };

    let public_input: PublicInputs = (&private_input).into();

    return Ok((public_input, private_input));
}

pub fn parse_email_with_domain(
    email_raw_data: &[u8],
    from_pepper: Vec<u8>,
    domain: &str,
) -> ParserResult<(PublicInputs, PrivateInputs)> {
    let s = String::from_utf8_lossy(email_raw_data);
    let email = Email::from_str(&s)?;

    let binding = dkim::Header::new(Default::default(), Default::default());
    let (dkim_msg, dkim_header) = match email
        .get_dkim_message()
        .into_iter()
        .zip(email.dkim_headers.iter())
        .find(|(_dkim_msg, dkim_header)| {
            if &dkim_header.sdid == domain {
                return true;
            } else {
                return false;
            }
        }) {
        Some((dkim_msg, dkim_header)) => (dkim_msg, dkim_header),
        None => (Default::default(), &binding),
    };

    let dkim_msg = dkim_msg.as_bytes();

    let from = email
        .get_header_item("from")
        .map_err(|e| ParserError::DkimParsingError(e.to_string()))?;

    let from = Email::<'_>::extract_address_of_from(from)
        .map_err(|e| ParserError::DkimParsingError(e.to_string()))?;

    parse_header(dkim_msg, dkim_header, from_pepper, from)
}

pub fn parse_email(
    email_raw_data: &[u8],
    from_pepper: Vec<u8>,
) -> ParserResult<(PublicInputs, PrivateInputs)> {
    let s = String::from_utf8_lossy(email_raw_data);
    let email = Email::from_str(&s)?;

    let binding = dkim::Header::new(Default::default(), Default::default());
    let (dkim_msg, dkim_header) = match email
        .get_dkim_message()
        .into_iter()
        .zip(email.dkim_headers.iter())
        .find(|(_dkim_msg, _dkim_header)| {
            return true;
        }) {
        Some((dkim_msg, dkim_header)) => (dkim_msg, dkim_header),
        None => (Default::default(), &binding),
    };

    let dkim_msg = dkim_msg.as_bytes();

    let from = email
        .get_header_item("from")
        .map_err(|e| ParserError::DkimParsingError(e.to_string()))?;

    let from = Email::<'_>::extract_address_of_from(from)
        .map_err(|e| ParserError::DkimParsingError(e.to_string()))?;

    parse_header(dkim_msg, dkim_header, from_pepper, from)
}
