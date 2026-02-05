//! Configuration types for corrosion-dns.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// DNS server configuration.
    pub dns: DnsConfig,

    /// Telemetry configuration.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

/// DNS server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Address for DNS server to listen on (UDP and TCP).
    pub listen_addr: SocketAddr,

    /// Base domain for apps (e.g., "apps.example.com").
    /// App domains will be subdomains of this.
    pub base_domain: String,

    /// TTL for DNS records in seconds.
    #[serde(default = "default_ttl")]
    pub ttl: u32,

    /// Corrosion API address to connect to.
    pub corrosion_addr: SocketAddr,

    /// SOA record configuration.
    #[serde(default)]
    pub soa: SoaConfig,

    /// Optional group filtering configuration.
    /// When present, enables source-IP-based group filtering on AAAA responses.
    #[serde(default)]
    pub group_filter: Option<GroupFilterConfig>,
}

/// Telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Log level filter (e.g., "info", "debug", "corrosion_dns=debug,warn").
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Prometheus metrics exporter address.
    #[serde(default)]
    pub prometheus_addr: Option<SocketAddr>,

    /// OpenTelemetry configuration.
    #[serde(default)]
    pub opentelemetry: Option<OpenTelemetryConfig>,
}

/// OpenTelemetry exporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenTelemetryConfig {
    /// OTLP endpoint (e.g., "http://localhost:4317").
    pub endpoint: String,

    /// Service name for traces.
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            prometheus_addr: None,
            opentelemetry: None,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_service_name() -> String {
    "corrosion-dns".to_string()
}

/// SOA (Start of Authority) record configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoaConfig {
    /// Primary nameserver hostname (e.g., "ns1.example.com").
    pub mname: String,

    /// Admin email in DNS format (e.g., "admin.example.com" for admin@example.com).
    pub rname: String,

    /// Refresh interval in seconds.
    #[serde(default = "default_refresh")]
    pub refresh: u32,

    /// Retry interval in seconds.
    #[serde(default = "default_retry")]
    pub retry: u32,

    /// Expire time in seconds.
    #[serde(default = "default_expire")]
    pub expire: u32,

    /// Minimum TTL in seconds.
    #[serde(default = "default_minimum")]
    pub minimum: u32,
}

fn default_ttl() -> u32 {
    60
}

fn default_refresh() -> u32 {
    3600
}

fn default_retry() -> u32 {
    600
}

fn default_expire() -> u32 {
    604800
}

fn default_minimum() -> u32 {
    60
}

/// Configuration for source-IP-based group filtering.
///
/// When enabled, AAAA query results are filtered so that only IPs whose
/// group hash (extracted from a configurable bit range within the IPv6
/// address) matches the querying client's group hash are returned.
///
/// IPv6 address layout:
/// ```text
/// fd00:a1b2:3456:NNNN:GGGG:GGGG:MMMM:MMMM
/// |___ 48 bits __|16b |_ 32 bits _|_ 32 bits _|
///    base prefix  node    group      machine
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupFilterConfig {
    /// Starting bit position (0-indexed from MSB) of the group hash
    /// within the 128-bit IPv6 address.
    #[serde(default = "default_group_start_bit")]
    pub group_start_bit: u8,

    /// Length of the group hash field in bits (max 32).
    #[serde(default = "default_group_bit_length")]
    pub group_bit_length: u8,
}

fn default_group_start_bit() -> u8 {
    64
}

fn default_group_bit_length() -> u8 {
    32
}

impl Default for GroupFilterConfig {
    fn default() -> Self {
        Self {
            group_start_bit: default_group_start_bit(),
            group_bit_length: default_group_bit_length(),
        }
    }
}

impl Default for SoaConfig {
    fn default() -> Self {
        Self {
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            refresh: default_refresh(),
            retry: default_retry(),
            expire: default_expire(),
            minimum: default_minimum(),
        }
    }
}
