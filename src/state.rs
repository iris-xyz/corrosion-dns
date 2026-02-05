//! In-memory DNS state backed by Corrosion subscriptions.
//!
//! Supports group-scoped DNS with search domains:
//! - `<app_name>.<base_domain>` returns all running machine IPs for the app
//! - `<region>.<app_name>.<base_domain>` returns IPs in that region only

use corro_api_types::ChangeId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tracing::debug;

use crate::metrics;

/// Represents an app's DNS data.
#[derive(Debug, Clone)]
pub struct AppDnsEntry {
    /// Unique app identifier.
    pub app_id: String,
    /// App name used as DNS subdomain (unique within group).
    pub app_name: String,
}

/// Represents a machine that can serve traffic.
#[derive(Debug, Clone)]
pub struct MachineDnsEntry {
    /// Unique machine identifier.
    pub machine_id: String,
    /// App this machine belongs to.
    pub app_id: String,
    /// IPv6 address of the machine.
    pub ipv6_address: Ipv6Addr,
    /// Machine status: pending, starting, running, stopping, stopped, failed.
    pub status: String,
    /// Region where machine is running (e.g., "iad", "cdg").
    pub region: String,
}

/// Thread-safe in-memory DNS state.
#[derive(Debug, Clone)]
pub struct DnsState {
    inner: Arc<RwLock<DnsStateInner>>,
}

#[derive(Debug)]
struct DnsStateInner {
    /// Base domain for DNS names (e.g., "internal").
    base_domain: String,

    /// app_id -> AppDnsEntry
    apps: HashMap<String, AppDnsEntry>,

    /// machine_id -> MachineDnsEntry
    machines: HashMap<String, MachineDnsEntry>,

    /// domain -> Vec<Ipv6Addr> (derived index for fast lookups)
    /// Contains both `<app_name>.<base_domain>` and `<region>.<app_name>.<base_domain>`
    domain_to_ips: HashMap<String, Vec<Ipv6Addr>>,

    /// Serial number for SOA (incremented on changes)
    serial: u32,

    /// Last seen change_id for apps subscription (for resume on reconnect)
    apps_last_change_id: Option<ChangeId>,

    /// Last seen change_id for machines subscription (for resume on reconnect)
    machines_last_change_id: Option<ChangeId>,

    /// True after apps EndOfQuery received
    apps_ready: bool,

    /// True after machines EndOfQuery received
    machines_ready: bool,
}

impl Default for DnsStateInner {
    fn default() -> Self {
        Self {
            base_domain: "internal".to_string(),
            apps: HashMap::new(),
            machines: HashMap::new(),
            domain_to_ips: HashMap::new(),
            serial: 0,
            apps_last_change_id: None,
            machines_last_change_id: None,
            apps_ready: false,
            machines_ready: false,
        }
    }
}

impl Default for DnsState {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsState {
    /// Create a new empty DNS state with default base domain ("internal").
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(DnsStateInner::default())),
        }
    }

    /// Create a new DNS state with the given base domain.
    pub fn with_base_domain(base_domain: &str) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DnsStateInner {
                base_domain: base_domain.to_string(),
                ..Default::default()
            })),
        }
    }

    /// Set the base domain (used for deriving DNS names from app names).
    pub fn set_base_domain(&self, base_domain: &str) {
        let mut inner = self.inner.write();
        inner.base_domain = base_domain.to_string();
        Self::rebuild_domain_index(&mut inner);
    }

    /// Insert or update an app.
    pub fn upsert_app(&self, app: AppDnsEntry) {
        let mut inner = self.inner.write();
        debug!(app_id = %app.app_id, app_name = %app.app_name, "upserting app");
        inner.apps.insert(app.app_id.clone(), app);
        inner.serial = inner.serial.wrapping_add(1);
        Self::rebuild_domain_index(&mut inner);
    }

    /// Remove an app by ID.
    pub fn remove_app(&self, app_id: &str) {
        let mut inner = self.inner.write();
        if inner.apps.remove(app_id).is_some() {
            debug!(app_id, "removed app");
            inner.serial = inner.serial.wrapping_add(1);
            Self::rebuild_domain_index(&mut inner);
        }
    }

    /// Insert or update a machine.
    pub fn upsert_machine(&self, machine: MachineDnsEntry) {
        let mut inner = self.inner.write();
        debug!(
            machine_id = %machine.machine_id,
            app_id = %machine.app_id,
            status = %machine.status,
            region = %machine.region,
            ipv6 = %machine.ipv6_address,
            "upserting machine"
        );
        inner.machines.insert(machine.machine_id.clone(), machine);
        inner.serial = inner.serial.wrapping_add(1);
        Self::rebuild_domain_index(&mut inner);
    }

    /// Remove a machine by ID.
    pub fn remove_machine(&self, machine_id: &str) {
        let mut inner = self.inner.write();
        if inner.machines.remove(machine_id).is_some() {
            debug!(machine_id, "removed machine");
            inner.serial = inner.serial.wrapping_add(1);
            Self::rebuild_domain_index(&mut inner);
        }
    }

    /// Lookup AAAA records for a domain.
    /// Returns empty vec if domain not found.
    pub fn lookup_aaaa(&self, domain: &str) -> Vec<Ipv6Addr> {
        let inner = self.inner.read();
        inner.domain_to_ips.get(domain).cloned().unwrap_or_default()
    }

    /// Check if the given domain exists in our state.
    pub fn has_domain(&self, domain: &str) -> bool {
        let inner = self.inner.read();
        inner.domain_to_ips.contains_key(domain)
    }

    /// Get current SOA serial.
    pub fn serial(&self) -> u32 {
        self.inner.read().serial
    }

    /// Check if state is ready to serve DNS queries.
    /// Ready means both apps and machines have completed initial sync.
    pub fn is_ready(&self) -> bool {
        let inner = self.inner.read();
        inner.apps_ready && inner.machines_ready
    }

    /// Mark apps subscription as ready (initial sync complete).
    pub fn mark_apps_ready(&self, change_id: Option<ChangeId>) {
        let mut inner = self.inner.write();
        inner.apps_ready = true;
        inner.apps_last_change_id = change_id;
        debug!(
            apps_ready = inner.apps_ready,
            machines_ready = inner.machines_ready,
            "apps subscription ready"
        );
    }

    /// Mark machines subscription as ready (initial sync complete).
    pub fn mark_machines_ready(&self, change_id: Option<ChangeId>) {
        let mut inner = self.inner.write();
        inner.machines_ready = true;
        inner.machines_last_change_id = change_id;
        debug!(
            apps_ready = inner.apps_ready,
            machines_ready = inner.machines_ready,
            "machines subscription ready"
        );
    }

    /// Update apps last change_id.
    pub fn set_apps_change_id(&self, change_id: ChangeId) {
        self.inner.write().apps_last_change_id = Some(change_id);
    }

    /// Update machines last change_id.
    pub fn set_machines_change_id(&self, change_id: ChangeId) {
        self.inner.write().machines_last_change_id = Some(change_id);
    }

    /// Get apps last change_id for subscription resume.
    pub fn apps_change_id(&self) -> Option<ChangeId> {
        self.inner.read().apps_last_change_id
    }

    /// Get machines last change_id for subscription resume.
    pub fn machines_change_id(&self) -> Option<ChangeId> {
        self.inner.read().machines_last_change_id
    }

    /// Clear all state (for full resync after MissedChange error).
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.apps.clear();
        inner.machines.clear();
        inner.domain_to_ips.clear();
        inner.apps_ready = false;
        inner.machines_ready = false;
        inner.apps_last_change_id = None;
        inner.machines_last_change_id = None;
        inner.serial = inner.serial.wrapping_add(1);
        debug!("cleared all DNS state for resync");
    }

    /// Get count of apps (for health check).
    pub fn apps_count(&self) -> usize {
        self.inner.read().apps.len()
    }

    /// Get count of machines (for health check).
    pub fn machines_count(&self) -> usize {
        self.inner.read().machines.len()
    }

    /// Get count of domains with at least one running machine.
    pub fn domains_count(&self) -> usize {
        self.inner.read().domain_to_ips.len()
    }

    /// Emit current state metrics.
    pub fn emit_metrics(&self) {
        let inner = self.inner.read();

        // Count running vs other machines
        let running = inner
            .machines
            .values()
            .filter(|m| m.status == "running")
            .count();
        let other = inner.machines.len() - running;

        metrics::record_state_counts(
            inner.apps.len(),
            inner.machines.len(),
            inner.domain_to_ips.len(),
        );
        metrics::record_machines_by_status(running, other);
        metrics::record_ready_state(inner.apps_ready, inner.machines_ready);
        metrics::record_serial(inner.serial);
    }

    /// Rebuild the domain->IPs index from apps and machines.
    ///
    /// Creates entries for:
    /// - `<app_name>.<base_domain>` -> all running machine IPs
    /// - `<region>.<app_name>.<base_domain>` -> running machine IPs in that region
    fn rebuild_domain_index(inner: &mut DnsStateInner) {
        inner.domain_to_ips.clear();

        for app in inner.apps.values() {
            // Get running machines for this app
            let running_machines: Vec<&MachineDnsEntry> = inner
                .machines
                .values()
                .filter(|m| m.app_id == app.app_id && m.status == "running")
                .collect();

            if running_machines.is_empty() {
                continue;
            }

            // Build app-level domain: <app_name>.<base_domain>
            let app_domain = format!("{}.{}", app.app_name, inner.base_domain);
            let all_ips: Vec<Ipv6Addr> = running_machines.iter().map(|m| m.ipv6_address).collect();
            inner.domain_to_ips.insert(app_domain, all_ips);

            // Build region-level domains: <region>.<app_name>.<base_domain>
            let mut region_ips: HashMap<&str, Vec<Ipv6Addr>> = HashMap::new();
            for machine in &running_machines {
                if !machine.region.is_empty() {
                    region_ips
                        .entry(machine.region.as_str())
                        .or_default()
                        .push(machine.ipv6_address);
                }
            }

            for (region, ips) in region_ips {
                let region_domain = format!("{}.{}.{}", region, app.app_name, inner.base_domain);
                inner.domain_to_ips.insert(region_domain, ips);
            }
        }

        debug!(domains = inner.domain_to_ips.len(), "rebuilt domain index");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app(app_id: &str, app_name: &str) -> AppDnsEntry {
        AppDnsEntry {
            app_id: app_id.to_string(),
            app_name: app_name.to_string(),
        }
    }

    fn make_machine(
        machine_id: &str,
        app_id: &str,
        ip: &str,
        status: &str,
        region: &str,
    ) -> MachineDnsEntry {
        MachineDnsEntry {
            machine_id: machine_id.to_string(),
            app_id: app_id.to_string(),
            ipv6_address: ip.parse().unwrap(),
            status: status.to_string(),
            region: region.to_string(),
        }
    }

    #[test]
    fn test_upsert_app_creates_entry() {
        let state = DnsState::new();
        state.upsert_app(make_app("app1", "my-api"));
        assert_eq!(state.apps_count(), 1);
    }

    #[test]
    fn test_upsert_machine_creates_entry() {
        let state = DnsState::new();
        state.upsert_machine(make_machine("m1", "app1", "fd00::1", "running", "iad"));
        assert_eq!(state.machines_count(), 1);
    }

    #[test]
    fn test_domain_derived_from_app_name() {
        let state = DnsState::with_base_domain("internal");

        state.upsert_app(make_app("app1", "my-api"));
        state.upsert_machine(make_machine("m1", "app1", "fd00::1", "running", "iad"));

        // Should resolve via <app_name>.<base_domain>
        let ips = state.lookup_aaaa("my-api.internal");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "fd00::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_regional_lookup() {
        let state = DnsState::with_base_domain("internal");

        state.upsert_app(make_app("app1", "my-api"));
        state.upsert_machine(make_machine("m1", "app1", "fd00::1", "running", "iad"));
        state.upsert_machine(make_machine("m2", "app1", "fd00::2", "running", "cdg"));

        // App-level lookup returns all
        let all_ips = state.lookup_aaaa("my-api.internal");
        assert_eq!(all_ips.len(), 2);

        // Regional lookups
        let iad_ips = state.lookup_aaaa("iad.my-api.internal");
        assert_eq!(iad_ips.len(), 1);
        assert_eq!(iad_ips[0], "fd00::1".parse::<Ipv6Addr>().unwrap());

        let cdg_ips = state.lookup_aaaa("cdg.my-api.internal");
        assert_eq!(cdg_ips.len(), 1);
        assert_eq!(cdg_ips[0], "fd00::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_domain_index_only_includes_running_machines() {
        let state = DnsState::with_base_domain("internal");

        state.upsert_app(make_app("app1", "my-api"));
        state.upsert_machine(make_machine("m1", "app1", "fd00::1", "running", "iad"));
        state.upsert_machine(make_machine("m2", "app1", "fd00::2", "stopped", "iad"));

        let ips = state.lookup_aaaa("my-api.internal");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "fd00::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_domain_index_updates_on_status_change() {
        let state = DnsState::with_base_domain("internal");

        state.upsert_app(make_app("app1", "my-api"));
        state.upsert_machine(make_machine("m1", "app1", "fd00::1", "running", "iad"));

        assert_eq!(state.lookup_aaaa("my-api.internal").len(), 1);

        // Change to stopped
        state.upsert_machine(make_machine("m1", "app1", "fd00::1", "stopped", "iad"));

        assert_eq!(state.lookup_aaaa("my-api.internal").len(), 0);
    }

    #[test]
    fn test_remove_app_clears_domain_index() {
        let state = DnsState::with_base_domain("internal");

        state.upsert_app(make_app("app1", "my-api"));
        state.upsert_machine(make_machine("m1", "app1", "fd00::1", "running", "iad"));

        assert!(state.has_domain("my-api.internal"));

        state.remove_app("app1");

        assert!(!state.has_domain("my-api.internal"));
    }

    #[test]
    fn test_serial_increments_on_change() {
        let state = DnsState::new();
        let initial = state.serial();

        state.upsert_app(make_app("app1", "my-api"));

        assert_eq!(state.serial(), initial + 1);
    }

    #[test]
    fn test_ready_flag() {
        let state = DnsState::new();
        assert!(!state.is_ready());

        state.mark_apps_ready(None);
        assert!(!state.is_ready());

        state.mark_machines_ready(None);
        assert!(state.is_ready());
    }

    #[test]
    fn test_clear_resets_state() {
        let state = DnsState::with_base_domain("internal");

        state.upsert_app(make_app("app1", "my-api"));
        state.mark_apps_ready(Some(ChangeId(100)));
        state.mark_machines_ready(Some(ChangeId(200)));

        assert!(state.is_ready());
        assert_eq!(state.apps_count(), 1);

        state.clear();

        assert!(!state.is_ready());
        assert_eq!(state.apps_count(), 0);
        assert!(state.apps_change_id().is_none());
    }

    #[test]
    fn test_set_base_domain_rebuilds_index() {
        let state = DnsState::with_base_domain("internal");

        state.upsert_app(make_app("app1", "my-api"));
        state.upsert_machine(make_machine("m1", "app1", "fd00::1", "running", "iad"));

        assert!(state.has_domain("my-api.internal"));

        state.set_base_domain("apps.example.com");

        assert!(!state.has_domain("my-api.internal"));
        assert!(state.has_domain("my-api.apps.example.com"));
    }
}
