//! Metrics instrumentation for corrosion-dns.
//!
//! All metrics are prefixed with `corro_dns.`

use metrics::{counter, gauge, histogram};
use std::time::Instant;

/// Record a DNS query.
pub fn record_query(record_type: &str, result: QueryResult, duration: std::time::Duration) {
    let result_str = match result {
        QueryResult::Success => "success",
        QueryResult::NxDomain => "nxdomain",
        QueryResult::NotReady => "not_ready",
        QueryResult::Error => "error",
    };

    counter!("corro_dns.query.count", "type" => record_type.to_string(), "result" => result_str)
        .increment(1);
    histogram!("corro_dns.query.duration.seconds", "type" => record_type.to_string())
        .record(duration.as_secs_f64());
}

/// Query result type for metrics.
#[derive(Debug, Clone, Copy)]
pub enum QueryResult {
    /// Query returned records successfully.
    Success,
    /// Domain not found.
    NxDomain,
    /// State not ready (initial sync incomplete).
    NotReady,
    /// Query failed with an error.
    Error,
}

/// Record a subscription event.
pub fn record_subscription_event(table: &str, event_type: SubscriptionEventType) {
    let event_str = match event_type {
        SubscriptionEventType::Insert => "insert",
        SubscriptionEventType::Update => "update",
        SubscriptionEventType::Delete => "delete",
        SubscriptionEventType::InitialRow => "initial_row",
        SubscriptionEventType::EndOfQuery => "end_of_query",
        SubscriptionEventType::Error => "error",
    };

    counter!("corro_dns.subscription.event.count", "table" => table.to_string(), "event" => event_str)
        .increment(1);
}

/// Subscription event types.
#[derive(Debug, Clone, Copy)]
pub enum SubscriptionEventType {
    /// New row inserted.
    Insert,
    /// Existing row updated.
    Update,
    /// Row deleted.
    Delete,
    /// Initial row during sync (before EndOfQuery).
    InitialRow,
    /// Initial query complete, live streaming starts.
    EndOfQuery,
    /// Error event from subscription.
    Error,
}

/// Record a subscription reconnect.
pub fn record_subscription_reconnect(table: &str, reason: ReconnectReason) {
    let reason_str = match reason {
        ReconnectReason::StreamEnded => "stream_ended",
        ReconnectReason::Error => "error",
        ReconnectReason::MissedChanges => "missed_changes",
        ReconnectReason::InitialConnect => "initial_connect",
    };

    counter!("corro_dns.subscription.reconnect.count", "table" => table.to_string(), "reason" => reason_str)
        .increment(1);
}

/// Reconnect reasons.
#[derive(Debug, Clone, Copy)]
pub enum ReconnectReason {
    /// Subscription stream ended normally.
    StreamEnded,
    /// Subscription encountered an error.
    Error,
    /// Missed changes detected, full resync needed.
    MissedChanges,
    /// First connection to Corrosion.
    InitialConnect,
}

/// Record state counts (call periodically or on change).
pub fn record_state_counts(apps: usize, machines: usize, domains: usize) {
    gauge!("corro_dns.state.apps.count").set(apps as f64);
    gauge!("corro_dns.state.machines.count").set(machines as f64);
    gauge!("corro_dns.state.domains.count").set(domains as f64);
}

/// Record machines by status.
pub fn record_machines_by_status(running: usize, other: usize) {
    gauge!("corro_dns.state.machines.running").set(running as f64);
    gauge!("corro_dns.state.machines.other").set(other as f64);
}

/// Record readiness state.
pub fn record_ready_state(apps_ready: bool, machines_ready: bool) {
    gauge!("corro_dns.state.apps_ready").set(if apps_ready { 1.0 } else { 0.0 });
    gauge!("corro_dns.state.machines_ready").set(if machines_ready { 1.0 } else { 0.0 });
}

/// Record the SOA serial number.
pub fn record_serial(serial: u32) {
    gauge!("corro_dns.state.serial").set(serial as f64);
}

/// Record a full state resync (due to missed changes).
pub fn record_state_resync() {
    counter!("corro_dns.state.resync.count").increment(1);
}

/// Record IPs returned for a successful AAAA lookup.
pub fn record_aaaa_ips_returned(count: usize) {
    histogram!("corro_dns.query.aaaa.ips_returned").record(count as f64);
}

/// Helper for timing operations.
pub struct Timer {
    start: Instant,
}

impl Timer {
    /// Start a new timer.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Get elapsed duration since timer start.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}
