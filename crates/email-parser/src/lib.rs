use error::ParserError;

pub mod error;
pub mod types;
pub mod parser;
pub mod dkim_keys;

pub type ParserResult<T> = Result<T, ParserError>;