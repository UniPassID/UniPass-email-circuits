use std::io;

use ark_serialize::SerializationError;

/// Error thrown by the server.
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}
