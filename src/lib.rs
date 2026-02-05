//! Corrosion DNS - An authoritative DNS server backed by Corrosion distributed state.
//!
//! This crate provides a DNS server that automatically serves DNS records based on
//! the state of applications and machines in a Corrosion cluster. It subscribes to
//! changes in the `apps` and `machines` tables and updates DNS records in real-time.
//!
//! ## Features
//!
//! - Real-time DNS updates via Corrosion subscriptions
//! - AAAA records for app domains pointing to running machine IPv6 addresses
//! - Automatic failover and reconnection to Corrosion
//! - Graceful shutdown support
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        corrosion-dns                            │
//! │                                                                 │
//! │  ┌──────────────────┐    ┌──────────────────┐                  │
//! │  │ Corrosion Client │───▶│   DNS State      │                  │
//! │  │ (subscriptions)  │    │   (in-memory)    │                  │
//! │  └──────────────────┘    └────────┬─────────┘                  │
//! │         │                         │                             │
//! │         │ Subscribe to:           │                             │
//! │         │ - apps                  ▼                             │
//! │         │ - machines         ┌──────────────────┐              │
//! │         │                    │  Hickory DNS     │◀── UDP/TCP   │
//! │         │                    │  Server          │    :53       │
//! │         └───────────────────▶└──────────────────┘              │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## DNS Resolution
//!
//! ```text
//! my-api-a1b2c3d4.apps.example.com
//!   → lookup app by domain
//!   → find machines where app_id matches AND status='running'
//!   → return AAAA records with machine IPv6 addresses
//! ```
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use corrosion_dns::{DnsConfig, DnsServer, SoaConfig};
//! use tripwire::Tripwire;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = DnsConfig {
//!         listen_addr: "[::]:5353".parse().unwrap(),
//!         base_domain: "apps.example.com".to_string(),
//!         ttl: 60,
//!         corrosion_addr: "127.0.0.1:8080".parse().unwrap(),
//!         soa: SoaConfig::default(),
//!         group_filter: None,
//!     };
//!
//!     let (tripwire, worker) = Tripwire::new_signals();
//!     tokio::spawn(worker);
//!
//!     let server = DnsServer::new(config);
//!     server.run(tripwire).await.unwrap();
//! }
//! ```

#![warn(missing_docs)]

pub mod authority;
pub mod config;
pub mod error;
pub mod metrics;
pub mod server;
pub mod state;
pub mod subscription;
pub mod telemetry;

// Re-export main types
pub use config::{Config, DnsConfig, GroupFilterConfig, SoaConfig, TelemetryConfig};
pub use error::DnsError;
pub use server::DnsServer;
pub use state::DnsState;
