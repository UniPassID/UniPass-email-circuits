use std::string::FromUtf8Error;

/// Error thrown by the server.
#[derive(Debug, thiserror::Error)]
pub enum ParserError {
    #[error("pubkey not found")]
    PubkeyNotFound,
    #[error("header format error")]
    HeaderFormatError,
    #[error("error:`{0}`")]
    SpecificError(String),
    #[error("dkim error: `{0}`")]
    DkimParsingError(String),
    #[error(transparent)]
    FromUtf8Error(#[from] FromUtf8Error),
}

impl From<email_rs::dkim::DkimParsingError> for ParserError {
    fn from(e: email_rs::dkim::DkimParsingError) -> Self {
        let err = format!("{:?}", e);
        ParserError::DkimParsingError(err)
    }
}
