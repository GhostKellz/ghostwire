use std::ffi::NulError;
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Pool error: {0}")]
    Pool(String),

    #[error("Type mismatch: expected {expected}, got {actual}")]
    TypeMismatch {
        expected: String,
        actual: String,
    },

    #[error("Null value error: {0}")]
    NullValue(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Post-quantum crypto error: {0}")]
    PostQuantum(String),

    #[error("FFI error: {0}")]
    Ffi(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("String error: {0}")]
    StringError(#[from] NulError),

    #[error("Other error: {0}")]
    Other(String),
}

impl Error {
    pub fn is_recoverable(&self) -> bool {
        match self {
            Error::Database(msg) => !msg.contains("corrupt") && !msg.contains("malformed"),
            Error::Connection(_) => true,
            Error::Pool(_) => true,
            Error::Timeout(_) => true,
            Error::Transaction(_) => true,
            _ => false,
        }
    }

    pub fn error_code(&self) -> i32 {
        match self {
            Error::Database(_) => 1,
            Error::Connection(_) => 2,
            Error::Pool(_) => 3,
            Error::TypeMismatch { .. } => 4,
            Error::NullValue(_) => 5,
            Error::InvalidParameter(_) => 6,
            Error::Transaction(_) => 7,
            Error::Timeout(_) => 8,
            Error::PostQuantum(_) => 9,
            Error::Ffi(_) => 10,
            Error::Io(_) => 11,
            Error::Utf8(_) => 12,
            Error::StringError(_) => 13,
            Error::Other(_) => 99,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;