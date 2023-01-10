use error::ParserError;

pub mod error;
pub mod parser;
pub mod types;

pub type ParserResult<T> = Result<T, ParserError>;
