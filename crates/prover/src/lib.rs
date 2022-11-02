use error::ProverError;

pub mod circuit;
pub mod error;
pub mod parameters;
pub mod types;
pub mod utils;

type ProverResult<T> = Result<T, ProverError>;
