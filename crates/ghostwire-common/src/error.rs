use thiserror::Error;

pub type Result<T> = std::result::Result<T, GhostWireError>;

#[derive(Error, Debug)]
pub enum GhostWireError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Authorization error: {0}")]
    Authz(String),

    #[error("Policy error: {0}")]
    Policy(String),

    #[error("WireGuard error: {0}")]
    WireGuard(String),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl GhostWireError {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn database(msg: impl Into<String>) -> Self {
        Self::Database(msg.into())
    }

    pub fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    pub fn authz(msg: impl Into<String>) -> Self {
        Self::Authz(msg.into())
    }

    pub fn policy(msg: impl Into<String>) -> Self {
        Self::Policy(msg.into())
    }

    pub fn wireguard(msg: impl Into<String>) -> Self {
        Self::WireGuard(msg.into())
    }

    pub fn quic(msg: impl Into<String>) -> Self {
        Self::Quic(msg.into())
    }

    pub fn dns(msg: impl Into<String>) -> Self {
        Self::Dns(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}