//! Subscription handlers for apps and machines tables.

use corro_api_types::{sqlite::ChangeType, SqliteValue, Statement, TypedQueryEvent};
use corro_client::sub::SubscriptionError;
use corro_client::CorrosionApiClient;
use futures::StreamExt;
use std::net::Ipv6Addr;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use tripwire::Tripwire;

use crate::error::DnsError;
use crate::metrics::{self, ReconnectReason, SubscriptionEventType};
use crate::state::{AppDnsEntry, DnsState, MachineDnsEntry};

/// Column indices for apps table query.
/// SELECT app_id, app_name FROM apps
mod apps_cols {
    pub const APP_ID: usize = 0;
    pub const APP_NAME: usize = 1;
}

/// Column indices for machines table query.
/// SELECT machine_id, app_id, ipv6_address, status, region FROM machines
mod machines_cols {
    pub const MACHINE_ID: usize = 0;
    pub const APP_ID: usize = 1;
    pub const IPV6_ADDRESS: usize = 2;
    pub const STATUS: usize = 3;
    pub const REGION: usize = 4;
}

/// Parse an app row from subscription values.
fn parse_app_row(values: &[SqliteValue]) -> Option<AppDnsEntry> {
    let app_id = values.get(apps_cols::APP_ID)?.as_str()?.to_string();
    let app_name = values.get(apps_cols::APP_NAME)?.as_str()?.to_string();

    Some(AppDnsEntry { app_id, app_name })
}

/// Get app_id from row values.
fn get_app_id(values: &[SqliteValue]) -> Option<String> {
    values.get(apps_cols::APP_ID)?.as_str().map(String::from)
}

/// Parse a machine row from subscription values.
fn parse_machine_row(values: &[SqliteValue]) -> Option<MachineDnsEntry> {
    let machine_id = values.get(machines_cols::MACHINE_ID)?.as_str()?.to_string();
    let app_id = values.get(machines_cols::APP_ID)?.as_str()?.to_string();
    let ipv6_str = values.get(machines_cols::IPV6_ADDRESS)?.as_str()?;
    let ipv6_address: Ipv6Addr = ipv6_str.parse().ok()?;
    let status = values
        .get(machines_cols::STATUS)
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let region = values
        .get(machines_cols::REGION)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(MachineDnsEntry {
        machine_id,
        app_id,
        ipv6_address,
        status,
        region,
    })
}

/// Get machine_id from row values.
fn get_machine_id(values: &[SqliteValue]) -> Option<String> {
    values
        .get(machines_cols::MACHINE_ID)?
        .as_str()
        .map(String::from)
}

/// Manages subscriptions to Corrosion tables.
pub struct SubscriptionHandler {
    client: CorrosionApiClient,
    state: DnsState,
}

impl SubscriptionHandler {
    /// Create a new subscription handler.
    pub fn new(client: CorrosionApiClient, state: DnsState) -> Self {
        Self { client, state }
    }

    /// Start subscriptions for apps and machines tables.
    /// Runs until tripwire is triggered.
    pub async fn run(self, tripwire: Tripwire) -> Result<(), DnsError> {
        // Spawn apps subscription
        let apps_handle = tokio::spawn({
            let client = self.client.clone();
            let state = self.state.clone();
            let tripwire = tripwire.clone();
            async move { Self::subscribe_apps(client, state, tripwire).await }
        });

        // Spawn machines subscription
        let machines_handle = tokio::spawn({
            let client = self.client.clone();
            let state = self.state.clone();
            let tripwire = tripwire.clone();
            async move { Self::subscribe_machines(client, state, tripwire).await }
        });

        // Wait for both to complete (on shutdown)
        let (apps_result, machines_result) = tokio::join!(apps_handle, machines_handle);

        if let Err(e) = apps_result {
            error!("Apps subscription task panicked: {}", e);
        }
        if let Err(e) = machines_result {
            error!("Machines subscription task panicked: {}", e);
        }

        Ok(())
    }

    /// Subscribe to apps table changes.
    async fn subscribe_apps(client: CorrosionApiClient, state: DnsState, tripwire: Tripwire) {
        let statement = Statement::Simple("SELECT app_id, app_name FROM apps".into());

        let mut backoff_secs = 1u64;
        const MAX_BACKOFF: u64 = 30;
        let mut first_connect = true;

        loop {
            // Check for shutdown before starting subscription
            if tripwire.is_shutting_down() {
                info!("Apps subscription shutting down");
                return;
            }

            info!("Starting apps subscription");

            // Get resume change_id if available
            let from = state.apps_change_id();

            let mut stream = match client.subscribe(&statement, false, from).await {
                Ok(s) => {
                    backoff_secs = 1; // Reset backoff on success
                    if first_connect {
                        metrics::record_subscription_reconnect(
                            "apps",
                            ReconnectReason::InitialConnect,
                        );
                        first_connect = false;
                    }
                    s
                }
                Err(e) => {
                    error!("Failed to subscribe to apps: {}", e);
                    metrics::record_subscription_reconnect("apps", ReconnectReason::Error);
                    sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
                    continue;
                }
            };

            // Process events until error or shutdown
            loop {
                tokio::select! {
                    biased;

                    _ = tripwire.clone() => {
                        info!("Apps subscription received shutdown signal");
                        return;
                    }

                    result = stream.next() => {
                        match result {
                            Some(Ok(event)) => {
                                Self::handle_apps_event(&state, event);
                            }
                            Some(Err(SubscriptionError::MissedChange { expected, got })) => {
                                warn!(
                                    expected = %expected,
                                    got = %got,
                                    "Missed changes in apps subscription, triggering full resync"
                                );
                                metrics::record_subscription_reconnect("apps", ReconnectReason::MissedChanges);
                                metrics::record_state_resync();
                                state.clear();
                                break; // Reconnect without change_id
                            }
                            Some(Err(e)) => {
                                warn!("Apps subscription error: {}", e);
                                metrics::record_subscription_reconnect("apps", ReconnectReason::Error);
                                break; // Reconnect
                            }
                            None => {
                                info!("Apps subscription stream ended");
                                metrics::record_subscription_reconnect("apps", ReconnectReason::StreamEnded);
                                break; // Reconnect
                            }
                        }
                    }
                }
            }

            // Brief delay before reconnecting
            sleep(Duration::from_secs(1)).await;
        }
    }

    /// Handle an apps subscription event.
    fn handle_apps_event(state: &DnsState, event: TypedQueryEvent<Vec<SqliteValue>>) {
        match event {
            TypedQueryEvent::Columns(cols) => {
                debug!(columns = ?cols, "apps subscription columns");
            }
            TypedQueryEvent::Row(_, ref values) => {
                if let Some(app) = parse_app_row(values) {
                    state.upsert_app(app);
                    metrics::record_subscription_event("apps", SubscriptionEventType::InitialRow);
                } else {
                    warn!("Failed to parse app row: {:?}", values);
                }
            }
            TypedQueryEvent::Change(ChangeType::Insert, _, ref values, change_id) => {
                if let Some(app) = parse_app_row(values) {
                    state.upsert_app(app);
                    metrics::record_subscription_event("apps", SubscriptionEventType::Insert);
                } else {
                    warn!("Failed to parse app row: {:?}", values);
                }
                state.set_apps_change_id(change_id);
            }
            TypedQueryEvent::Change(ChangeType::Update, _, ref values, change_id) => {
                if let Some(app) = parse_app_row(values) {
                    state.upsert_app(app);
                    metrics::record_subscription_event("apps", SubscriptionEventType::Update);
                } else {
                    warn!("Failed to parse app row: {:?}", values);
                }
                state.set_apps_change_id(change_id);
            }
            TypedQueryEvent::Change(ChangeType::Delete, _, ref values, change_id) => {
                if let Some(app_id) = get_app_id(values) {
                    state.remove_app(&app_id);
                    metrics::record_subscription_event("apps", SubscriptionEventType::Delete);
                }
                state.set_apps_change_id(change_id);
            }
            TypedQueryEvent::EndOfQuery { change_id, time } => {
                debug!(time, change_id = ?change_id, "apps initial query complete");
                metrics::record_subscription_event("apps", SubscriptionEventType::EndOfQuery);
                state.mark_apps_ready(change_id);
            }
            TypedQueryEvent::Error(msg) => {
                error!("Apps subscription error event: {}", msg);
                metrics::record_subscription_event("apps", SubscriptionEventType::Error);
            }
        }
    }

    /// Subscribe to machines table changes.
    async fn subscribe_machines(client: CorrosionApiClient, state: DnsState, tripwire: Tripwire) {
        // Subscribe to ALL machines with an app_id, filter status in the handler
        // This allows us to handle transitions (running -> stopped)
        let statement = Statement::Simple(
            "SELECT machine_id, app_id, ipv6_address, status, region FROM machines WHERE app_id IS NOT NULL".into(),
        );

        let mut backoff_secs = 1u64;
        const MAX_BACKOFF: u64 = 30;
        let mut first_connect = true;

        loop {
            if tripwire.is_shutting_down() {
                info!("Machines subscription shutting down");
                return;
            }

            info!("Starting machines subscription");

            let from = state.machines_change_id();

            let mut stream = match client.subscribe(&statement, false, from).await {
                Ok(s) => {
                    backoff_secs = 1;
                    if first_connect {
                        metrics::record_subscription_reconnect(
                            "machines",
                            ReconnectReason::InitialConnect,
                        );
                        first_connect = false;
                    }
                    s
                }
                Err(e) => {
                    error!("Failed to subscribe to machines: {}", e);
                    metrics::record_subscription_reconnect("machines", ReconnectReason::Error);
                    sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
                    continue;
                }
            };

            loop {
                tokio::select! {
                    biased;

                    _ = tripwire.clone() => {
                        info!("Machines subscription received shutdown signal");
                        return;
                    }

                    result = stream.next() => {
                        match result {
                            Some(Ok(event)) => {
                                Self::handle_machines_event(&state, event);
                            }
                            Some(Err(SubscriptionError::MissedChange { expected, got })) => {
                                warn!(
                                    expected = %expected,
                                    got = %got,
                                    "Missed changes in machines subscription, triggering full resync"
                                );
                                metrics::record_subscription_reconnect("machines", ReconnectReason::MissedChanges);
                                metrics::record_state_resync();
                                state.clear();
                                break;
                            }
                            Some(Err(e)) => {
                                warn!("Machines subscription error: {}", e);
                                metrics::record_subscription_reconnect("machines", ReconnectReason::Error);
                                break;
                            }
                            None => {
                                info!("Machines subscription stream ended");
                                metrics::record_subscription_reconnect("machines", ReconnectReason::StreamEnded);
                                break;
                            }
                        }
                    }
                }
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    /// Handle a machines subscription event.
    fn handle_machines_event(state: &DnsState, event: TypedQueryEvent<Vec<SqliteValue>>) {
        match event {
            TypedQueryEvent::Columns(cols) => {
                debug!(columns = ?cols, "machines subscription columns");
            }
            TypedQueryEvent::Row(_, ref values) => {
                if let Some(machine) = parse_machine_row(values) {
                    state.upsert_machine(machine);
                    metrics::record_subscription_event(
                        "machines",
                        SubscriptionEventType::InitialRow,
                    );
                } else {
                    warn!("Failed to parse machine row: {:?}", values);
                }
            }
            TypedQueryEvent::Change(ChangeType::Insert, _, ref values, change_id) => {
                if let Some(machine) = parse_machine_row(values) {
                    state.upsert_machine(machine);
                    metrics::record_subscription_event("machines", SubscriptionEventType::Insert);
                } else {
                    warn!("Failed to parse machine row: {:?}", values);
                }
                state.set_machines_change_id(change_id);
            }
            TypedQueryEvent::Change(ChangeType::Update, _, ref values, change_id) => {
                if let Some(machine) = parse_machine_row(values) {
                    state.upsert_machine(machine);
                    metrics::record_subscription_event("machines", SubscriptionEventType::Update);
                } else {
                    warn!("Failed to parse machine row: {:?}", values);
                }
                state.set_machines_change_id(change_id);
            }
            TypedQueryEvent::Change(ChangeType::Delete, _, ref values, change_id) => {
                if let Some(machine_id) = get_machine_id(values) {
                    state.remove_machine(&machine_id);
                    metrics::record_subscription_event("machines", SubscriptionEventType::Delete);
                }
                state.set_machines_change_id(change_id);
            }
            TypedQueryEvent::EndOfQuery { change_id, time } => {
                debug!(time, change_id = ?change_id, "machines initial query complete");
                metrics::record_subscription_event("machines", SubscriptionEventType::EndOfQuery);
                state.mark_machines_ready(change_id);
            }
            TypedQueryEvent::Error(msg) => {
                error!("Machines subscription error event: {}", msg);
                metrics::record_subscription_event("machines", SubscriptionEventType::Error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_app_row_valid() {
        let values = vec![
            SqliteValue::Text("app123".into()),
            SqliteValue::Text("my-api".into()),
        ];

        let app = parse_app_row(&values).unwrap();
        assert_eq!(app.app_id, "app123");
        assert_eq!(app.app_name, "my-api");
    }

    #[test]
    fn test_parse_app_row_missing_field_returns_none() {
        let values = vec![SqliteValue::Text("app123".into())];
        assert!(parse_app_row(&values).is_none());
    }

    #[test]
    fn test_parse_machine_row_valid() {
        let values = vec![
            SqliteValue::Text("machine1".into()),
            SqliteValue::Text("app123".into()),
            SqliteValue::Text("fd00::1".into()),
            SqliteValue::Text("running".into()),
            SqliteValue::Text("iad".into()),
        ];

        let machine = parse_machine_row(&values).unwrap();
        assert_eq!(machine.machine_id, "machine1");
        assert_eq!(machine.app_id, "app123");
        assert_eq!(machine.ipv6_address, "fd00::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(machine.status, "running");
        assert_eq!(machine.region, "iad");
    }

    #[test]
    fn test_parse_machine_row_invalid_ipv6_returns_none() {
        let values = vec![
            SqliteValue::Text("machine1".into()),
            SqliteValue::Text("app123".into()),
            SqliteValue::Text("not-an-ip".into()),
            SqliteValue::Text("running".into()),
            SqliteValue::Text("iad".into()),
        ];

        assert!(parse_machine_row(&values).is_none());
    }
}
