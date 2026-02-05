//! Error types for corrosion-dns.

use thiserror::Error;

/// Errors that can occur in the DNS server.
#[derive(Debug, Error)]
pub enum DnsError {
    /// IO error (network, file, etc.)
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Corrosion client error
    #[error("Corrosion client error: {0}")]
    Client(#[from] corro_client::Error),

    /// Subscription stream error
    #[error("Subscription error: {0}")]
    Subscription(#[from] corro_client::sub::SubscriptionError),

    /// HTTP client error (from corro-client initialization)
    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    Config(String),

    /// DNS protocol error
    #[error("DNS protocol error: {0}")]
    Proto(#[from] hickory_proto::ProtoError),

    /// Failed to parse address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// State not ready
    #[error("DNS state not ready - initial sync incomplete")]
    NotReady,
}
