use error::ParserError;

pub mod dkim_keys;
pub mod error;
pub mod parser;
pub mod types;

pub type ParserResult<T> = Result<T, ParserError>;
