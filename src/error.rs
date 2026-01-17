//! Error types for the Shredder Engine

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShredderError {
    #[error("Failed to read file: {0}")]
    FileRead(#[from] std::io::Error),

    #[error("Invalid PE file: {0}")]
    InvalidPE(String),

    #[error("Section not found: {0}")]
    SectionNotFound(String),

    #[error("Failed to encode instructions: {0}")]
    EncodingError(String),

    #[error("PE rebuild failed: {0}")]
    RebuildError(String),
}
