use std::io;

use plonk::ark_serialize::SerializationError;

/// Error thrown by the server.
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("error:`{0}`")]
    SpecificError(String),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}
