//! DNS server setup and lifecycle management.

use corro_client::CorrosionApiClient;
use hickory_server::authority::{AuthorityObject, Catalog};
use hickory_server::ServerFuture;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info};
use tripwire::Tripwire;

use crate::authority::CorrosionAuthority;
use crate::config::DnsConfig;
use crate::error::DnsError;
use crate::state::DnsState;
use crate::subscription::SubscriptionHandler;

/// Interval for emitting state metrics.
const METRICS_INTERVAL: Duration = Duration::from_secs(10);

/// Periodically emit state metrics.
async fn metrics_loop(state: DnsState, mut tripwire: Tripwire) {
    let mut interval = tokio::time::interval(METRICS_INTERVAL);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                state.emit_metrics();
                debug!(
                    apps = state.apps_count(),
                    machines = state.machines_count(),
                    domains = state.domains_count(),
                    "emitted state metrics"
                );
            }
            _ = &mut tripwire => {
                debug!("metrics loop shutting down");
                return;
            }
        }
    }
}

/// DNS server backed by Corrosion distributed state.
pub struct DnsServer {
    config: DnsConfig,
    state: DnsState,
}

impl DnsServer {
    /// Create a new DNS server with the given configuration.
    pub fn new(config: DnsConfig) -> Self {
        Self {
            config,
            state: DnsState::new(),
        }
    }

    /// Get a reference to the DNS state.
    pub fn state(&self) -> &DnsState {
        &self.state
    }

    /// Run the DNS server until the tripwire is triggered.
    pub async fn run(self, tripwire: Tripwire) -> Result<(), DnsError> {
        info!(
            listen_addr = %self.config.listen_addr,
            base_domain = %self.config.base_domain,
            corrosion_addr = %self.config.corrosion_addr,
            "Starting corrosion-dns server"
        );

        // Create Corrosion client
        let client = CorrosionApiClient::new(self.config.corrosion_addr)?;

        // Start subscription handler
        let subscription_handler = SubscriptionHandler::new(client.clone(), self.state.clone());

        let sub_tripwire = tripwire.clone();
        let sub_handle = tokio::spawn(async move {
            if let Err(e) = subscription_handler.run(sub_tripwire).await {
                error!("Subscription handler error: {}", e);
            }
        });

        // Wait for initial sync before starting DNS server
        info!("Waiting for initial state sync from Corrosion...");
        let dns_tripwire = tripwire.clone();
        loop {
            if tripwire.is_shutting_down() {
                info!("Shutdown requested before state sync completed");
                let _ = sub_handle.await;
                return Ok(());
            }

            if self.state.is_ready() {
                info!(
                    apps = self.state.apps_count(),
                    machines = self.state.machines_count(),
                    "Initial state sync complete"
                );
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Create authority and catalog
        let authority = CorrosionAuthority::new(self.config.clone(), self.state.clone())?;

        let mut catalog = Catalog::new();
        let authority: Arc<dyn AuthorityObject> = Arc::new(authority);
        catalog.upsert(authority.origin().clone(), vec![authority]);

        // Create server
        let mut server = ServerFuture::new(catalog);

        // Bind UDP
        let udp_socket = UdpSocket::bind(self.config.listen_addr).await?;
        info!(addr = %self.config.listen_addr, "DNS UDP listening");
        server.register_socket(udp_socket);

        // Bind TCP
        let tcp_listener = TcpListener::bind(self.config.listen_addr).await?;
        info!(addr = %self.config.listen_addr, "DNS TCP listening");
        server.register_listener(tcp_listener, Duration::from_secs(30));

        info!(
            base_domain = %self.config.base_domain,
            "DNS server ready to serve queries"
        );

        // Start metrics loop
        let metrics_state = self.state.clone();
        let metrics_tripwire = tripwire.clone();
        let metrics_handle = tokio::spawn(async move {
            metrics_loop(metrics_state, metrics_tripwire).await;
        });

        // Emit initial metrics
        self.state.emit_metrics();

        // Run server until tripwire
        tokio::select! {
            _ = dns_tripwire => {
                info!("DNS server shutdown requested");
            }
            result = server.block_until_done() => {
                if let Err(e) = result {
                    error!("DNS server error: {}", e);
                }
            }
        }

        // Wait for metrics loop to stop
        let _ = metrics_handle.await;

        // Wait for subscription handler to stop
        info!("Waiting for subscription handler to stop...");
        let _ = sub_handle.await;

        info!("DNS server stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SoaConfig;

    #[test]
    fn test_server_creation() {
        let config = DnsConfig {
            listen_addr: "127.0.0.1:5353".parse().unwrap(),
            base_domain: "apps.example.com".to_string(),
            ttl: 60,
            corrosion_addr: "127.0.0.1:8080".parse().unwrap(),
            soa: SoaConfig::default(),
        };

        let server = DnsServer::new(config);
        assert!(!server.state().is_ready());
    }
}
