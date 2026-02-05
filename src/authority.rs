//! Custom Hickory DNS authority backed by Corrosion state.

use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{AAAA, SOA};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordSet, RecordType};
use hickory_server::authority::{
    Authority, LookupControlFlow, LookupError, LookupOptions, LookupRecords, MessageRequest,
    UpdateResult, ZoneType,
};
use hickory_server::server::RequestInfo;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, trace};

use crate::config::{DnsConfig, GroupFilterConfig};
use crate::metrics::{self, QueryResult, Timer};
use crate::state::DnsState;

/// Extract a bit range from a 128-bit IPv6 address as a u32.
///
/// `start_bit` is 0-indexed from the MSB. `bit_length` is at most 32.
fn extract_bits_u32(addr: &Ipv6Addr, start_bit: u8, bit_length: u8) -> u32 {
    let bits = u128::from_be_bytes(addr.octets());
    let shift = 128 - start_bit as u32 - bit_length as u32;
    let mask = if bit_length == 32 {
        u32::MAX as u128
    } else {
        (1u128 << bit_length) - 1
    };
    ((bits >> shift) & mask) as u32
}

/// Extract the group hash from an IP address using the given config.
/// Returns `None` for IPv4 and IPv4-mapped IPv6 addresses.
fn extract_group_hash(addr: &IpAddr, config: &GroupFilterConfig) -> Option<u32> {
    match addr {
        IpAddr::V6(v6) => {
            if v6.to_ipv4_mapped().is_some() {
                return None;
            }
            Some(extract_bits_u32(
                v6,
                config.group_start_bit,
                config.group_bit_length,
            ))
        }
        IpAddr::V4(_) => None,
    }
}

/// Custom authority backed by Corrosion-derived DNS state.
pub struct CorrosionAuthority {
    origin: LowerName,
    state: DnsState,
    config: Arc<DnsConfig>,
}

impl CorrosionAuthority {
    /// Create a new authority for the given configuration and state.
    pub fn new(config: DnsConfig, state: DnsState) -> Result<Self, hickory_proto::ProtoError> {
        let origin = Name::from_ascii(&config.base_domain)?.into();

        Ok(Self {
            origin,
            state,
            config: Arc::new(config),
        })
    }

    /// Build AAAA records for the given name and IPs.
    fn build_aaaa_records(&self, name: Name, ips: &[Ipv6Addr]) -> RecordSet {
        let mut record_set = RecordSet::new(name.clone(), RecordType::AAAA, 0);

        for ip in ips {
            let mut record =
                Record::from_rdata(name.clone(), self.config.ttl, RData::AAAA(AAAA::from(*ip)));
            record.set_dns_class(hickory_proto::rr::DNSClass::IN);
            record_set.insert(record, 0);
        }

        record_set
    }

    /// Build the SOA record for this zone.
    fn build_soa_record(&self) -> RecordSet {
        let soa = SOA::new(
            Name::from_ascii(&self.config.soa.mname).unwrap_or_else(|_| Name::root()),
            Name::from_ascii(&self.config.soa.rname).unwrap_or_else(|_| Name::root()),
            self.state.serial(),
            self.config.soa.refresh as i32,
            self.config.soa.retry as i32,
            self.config.soa.expire as i32,
            self.config.soa.minimum,
        );

        let name = Name::from(self.origin.clone());
        let mut record_set = RecordSet::new(name.clone(), RecordType::SOA, 0);
        let mut record = Record::from_rdata(name, self.config.ttl, RData::SOA(soa));
        record.set_dns_class(hickory_proto::rr::DNSClass::IN);
        record_set.insert(record, 0);

        record_set
    }

    /// Perform an AAAA lookup with source-IP-based group filtering.
    fn lookup_aaaa_with_group_filter(
        &self,
        name: &LowerName,
        src: &SocketAddr,
        group_config: &GroupFilterConfig,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<LookupRecords> {
        let timer = Timer::start();
        let rtype_str = "AAAA";

        if !self.state.is_ready() {
            debug!("DNS state not ready, returning SERVFAIL");
            metrics::record_query(rtype_str, QueryResult::NotReady, timer.elapsed());
            return LookupControlFlow::Break(Err(LookupError::from(io::Error::new(
                io::ErrorKind::NotConnected,
                "DNS state not ready - initial sync incomplete",
            ))));
        }

        let name_str = name.to_string();
        let lookup_name = name_str.trim_end_matches('.');
        let all_ips = self.state.lookup_aaaa(lookup_name);

        if all_ips.is_empty() {
            debug!(name = %lookup_name, "AAAA lookup: no records found");
            metrics::record_query(rtype_str, QueryResult::NxDomain, timer.elapsed());
            return LookupControlFlow::Break(Err(LookupError::ResponseCode(
                ResponseCode::NXDomain,
            )));
        }

        let source_group = extract_group_hash(&src.ip(), group_config);

        let filtered_ips: Vec<Ipv6Addr> = match source_group {
            Some(src_hash) => all_ips
                .into_iter()
                .filter(|ip| {
                    extract_bits_u32(
                        ip,
                        group_config.group_start_bit,
                        group_config.group_bit_length,
                    ) == src_hash
                })
                .collect(),
            None => {
                debug!(name = %lookup_name, src = %src, "group filter: source is IPv4, skipping");
                all_ips
            }
        };

        if filtered_ips.is_empty() {
            debug!(name = %lookup_name, src = %src, "AAAA lookup: no IPs match source group");
            metrics::record_query(rtype_str, QueryResult::GroupDenied, timer.elapsed());
            metrics::record_group_denied();
            return LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::Refused)));
        }

        debug!(name = %lookup_name, count = filtered_ips.len(), "AAAA lookup with group filter");
        metrics::record_aaaa_ips_returned(filtered_ips.len());
        metrics::record_query(rtype_str, QueryResult::Success, timer.elapsed());
        let dns_name = Name::from(name.clone());
        let record_set = Arc::new(self.build_aaaa_records(dns_name, &filtered_ips));
        LookupControlFlow::Break(Ok(LookupRecords::new(lookup_options, record_set)))
    }

    /// Build an NS record for this zone.
    fn build_ns_record(&self) -> RecordSet {
        let name = Name::from(self.origin.clone());
        let ns_name = Name::from_ascii(&self.config.soa.mname).unwrap_or_else(|_| Name::root());

        let mut record_set = RecordSet::new(name.clone(), RecordType::NS, 0);
        let mut record = Record::from_rdata(
            name,
            self.config.ttl,
            RData::NS(hickory_proto::rr::rdata::NS(ns_name)),
        );
        record.set_dns_class(hickory_proto::rr::DNSClass::IN);
        record_set.insert(record, 0);

        record_set
    }
}

#[async_trait]
impl Authority for CorrosionAuthority {
    type Lookup = LookupRecords;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        let timer = Timer::start();
        let rtype_str = format!("{:?}", rtype);

        // Check if state is ready
        if !self.state.is_ready() {
            debug!("DNS state not ready, returning SERVFAIL");
            metrics::record_query(&rtype_str, QueryResult::NotReady, timer.elapsed());
            return LookupControlFlow::Break(Err(LookupError::from(io::Error::new(
                io::ErrorKind::NotConnected,
                "DNS state not ready - initial sync incomplete",
            ))));
        }

        let name_str = name.to_string();
        // Remove trailing dot if present for lookup
        let lookup_name = name_str.trim_end_matches('.');

        trace!(name = %lookup_name, rtype = ?rtype, "DNS lookup");

        match rtype {
            RecordType::AAAA => {
                let ips = self.state.lookup_aaaa(lookup_name);
                if ips.is_empty() {
                    debug!(name = %lookup_name, "AAAA lookup: no records found");
                    metrics::record_query(&rtype_str, QueryResult::NxDomain, timer.elapsed());
                    LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NXDomain)))
                } else {
                    debug!(name = %lookup_name, count = ips.len(), "AAAA lookup: returning records");
                    metrics::record_aaaa_ips_returned(ips.len());
                    metrics::record_query(&rtype_str, QueryResult::Success, timer.elapsed());
                    let dns_name = Name::from(name.clone());
                    let record_set = Arc::new(self.build_aaaa_records(dns_name, &ips));
                    LookupControlFlow::Break(Ok(LookupRecords::new(lookup_options, record_set)))
                }
            }
            RecordType::SOA => {
                debug!(name = %lookup_name, "SOA lookup");
                metrics::record_query(&rtype_str, QueryResult::Success, timer.elapsed());
                let record_set = Arc::new(self.build_soa_record());
                LookupControlFlow::Break(Ok(LookupRecords::new(lookup_options, record_set)))
            }
            RecordType::NS => {
                debug!(name = %lookup_name, "NS lookup");
                metrics::record_query(&rtype_str, QueryResult::Success, timer.elapsed());
                let record_set = Arc::new(self.build_ns_record());
                LookupControlFlow::Break(Ok(LookupRecords::new(lookup_options, record_set)))
            }
            RecordType::A => {
                // We only serve AAAA records
                debug!(name = %lookup_name, "A lookup: IPv4 not supported");
                metrics::record_query(&rtype_str, QueryResult::NxDomain, timer.elapsed());
                LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
            }
            _ => {
                trace!(name = %lookup_name, rtype = ?rtype, "Unsupported record type");
                metrics::record_query(&rtype_str, QueryResult::NxDomain, timer.elapsed());
                LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
            }
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        // Route AAAA queries through group filter when enabled
        if request_info.query.query_type() == RecordType::AAAA {
            if let Some(ref group_config) = self.config.group_filter {
                return self.lookup_aaaa_with_group_filter(
                    request_info.query.name(),
                    &request_info.src,
                    group_config,
                    lookup_options,
                );
            }
        }

        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        // DNSSEC not supported
        LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        // Dynamic updates not supported
        Err(ResponseCode::NotImp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GroupFilterConfig, SoaConfig};
    use crate::state::{AppDnsEntry, MachineDnsEntry};
    use hickory_proto::op::{Header, LowerQuery, Query};
    use hickory_server::proto::xfer::Protocol;

    fn test_config() -> DnsConfig {
        DnsConfig {
            listen_addr: "127.0.0.1:5353".parse().unwrap(),
            base_domain: "apps.example.com".to_string(),
            ttl: 60,
            corrosion_addr: "127.0.0.1:8080".parse().unwrap(),
            soa: SoaConfig::default(),
            group_filter: None,
        }
    }

    fn test_config_with_group_filter() -> DnsConfig {
        DnsConfig {
            group_filter: Some(GroupFilterConfig::default()),
            ..test_config()
        }
    }

    #[tokio::test]
    async fn test_lookup_aaaa_returns_ips() {
        // State must use same base_domain as config
        let state = DnsState::with_base_domain("apps.example.com");

        // Add app and running machine
        state.upsert_app(AppDnsEntry {
            app_id: "app1".to_string(),
            app_name: "test".to_string(),
        });
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m1".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00::1".parse().unwrap(),
            status: "running".to_string(),
            region: "us-east".to_string(),
        });
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        let authority = CorrosionAuthority::new(test_config(), state).unwrap();

        // Query for test.apps.example.com (app_name.base_domain)
        let name: LowerName = Name::from_ascii("test.apps.example.com").unwrap().into();
        let result = authority
            .lookup(&name, RecordType::AAAA, LookupOptions::default())
            .await;

        assert!(matches!(result, LookupControlFlow::Break(Ok(_))));
    }

    #[tokio::test]
    async fn test_lookup_aaaa_nxdomain_for_unknown() {
        let state = DnsState::with_base_domain("apps.example.com");
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        let authority = CorrosionAuthority::new(test_config(), state).unwrap();

        let name: LowerName = Name::from_ascii("unknown.apps.example.com").unwrap().into();
        let result = authority
            .lookup(&name, RecordType::AAAA, LookupOptions::default())
            .await;

        assert!(matches!(
            result,
            LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NXDomain)))
        ));
    }

    #[tokio::test]
    async fn test_lookup_soa() {
        let state = DnsState::with_base_domain("apps.example.com");
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        let authority = CorrosionAuthority::new(test_config(), state).unwrap();

        let name: LowerName = Name::from_ascii("apps.example.com").unwrap().into();
        let result = authority
            .lookup(&name, RecordType::SOA, LookupOptions::default())
            .await;

        assert!(matches!(result, LookupControlFlow::Break(Ok(_))));
    }

    #[tokio::test]
    async fn test_lookup_fails_when_not_ready() {
        let state = DnsState::with_base_domain("apps.example.com");
        // Don't mark as ready

        let authority = CorrosionAuthority::new(test_config(), state).unwrap();

        let name: LowerName = Name::from_ascii("test.apps.example.com").unwrap().into();
        let result = authority
            .lookup(&name, RecordType::AAAA, LookupOptions::default())
            .await;

        assert!(matches!(result, LookupControlFlow::Break(Err(_))));
    }

    #[tokio::test]
    async fn test_lookup_regional() {
        let state = DnsState::with_base_domain("apps.example.com");

        state.upsert_app(AppDnsEntry {
            app_id: "app1".to_string(),
            app_name: "my-api".to_string(),
        });
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m1".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00::1".parse().unwrap(),
            status: "running".to_string(),
            region: "iad".to_string(),
        });
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m2".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00::2".parse().unwrap(),
            status: "running".to_string(),
            region: "cdg".to_string(),
        });
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        let authority = CorrosionAuthority::new(test_config(), state).unwrap();

        // Regional lookup: iad.my-api.apps.example.com
        let name: LowerName = Name::from_ascii("iad.my-api.apps.example.com")
            .unwrap()
            .into();
        let result = authority
            .lookup(&name, RecordType::AAAA, LookupOptions::default())
            .await;

        assert!(matches!(result, LookupControlFlow::Break(Ok(_))));
    }

    // --- extract_bits_u32 tests ---

    #[test]
    fn test_extract_bits_u32_standard_layout() {
        // fd00:0000:0000:0001:AAAA:BBBB:0001:0001
        // Group at bits 64-95 = 0xAAAABBBB
        let addr: Ipv6Addr = "fd00:0:0:1:aaaa:bbbb:1:1".parse().unwrap();
        assert_eq!(extract_bits_u32(&addr, 64, 32), 0xAAAABBBB);
    }

    #[test]
    fn test_extract_bits_u32_all_zeros() {
        let addr: Ipv6Addr = "::".parse().unwrap();
        assert_eq!(extract_bits_u32(&addr, 64, 32), 0);
    }

    #[test]
    fn test_extract_bits_u32_all_ones() {
        let addr: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(extract_bits_u32(&addr, 64, 32), 0xFFFFFFFF);
    }

    #[test]
    fn test_extract_bits_u32_custom_range() {
        // Extract bits 48-63 (node field)
        let addr: Ipv6Addr = "fd00:0:0:abcd:0:0:0:0".parse().unwrap();
        assert_eq!(extract_bits_u32(&addr, 48, 16), 0xABCD);
    }

    // --- extract_group_hash tests ---

    #[test]
    fn test_extract_group_hash_ipv4_returns_none() {
        let config = GroupFilterConfig::default();
        let addr = IpAddr::V4("10.0.0.1".parse().unwrap());
        assert_eq!(extract_group_hash(&addr, &config), None);
    }

    #[test]
    fn test_extract_group_hash_ipv6_returns_hash() {
        let config = GroupFilterConfig::default();
        let addr = IpAddr::V6("fd00:0:0:1:aaaa:bbbb:1:1".parse().unwrap());
        assert_eq!(extract_group_hash(&addr, &config), Some(0xAAAABBBB));
    }

    #[test]
    fn test_extract_group_hash_ipv4_mapped_returns_none() {
        let config = GroupFilterConfig::default();
        // ::ffff:10.0.0.1
        let addr = IpAddr::V6("::ffff:10.0.0.1".parse().unwrap());
        assert_eq!(extract_group_hash(&addr, &config), None);
    }

    // --- search() with group filter tests ---

    fn make_request_info<'a>(
        src: SocketAddr,
        header: &'a Header,
        query: &'a LowerQuery,
    ) -> RequestInfo<'a> {
        RequestInfo::new(src, Protocol::Udp, header, query)
    }

    #[tokio::test]
    async fn test_search_group_filter_matching_returns_records() {
        let state = DnsState::with_base_domain("apps.example.com");

        state.upsert_app(AppDnsEntry {
            app_id: "app1".to_string(),
            app_name: "test".to_string(),
        });
        // Machine with group hash 0xAAAABBBB
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m1".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00:0:0:1:aaaa:bbbb:0:1".parse().unwrap(),
            status: "running".to_string(),
            region: "iad".to_string(),
        });
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        let authority = CorrosionAuthority::new(test_config_with_group_filter(), state).unwrap();

        // Source from same group (aaaa:bbbb)
        let src: SocketAddr = "[fd00:0:0:1:aaaa:bbbb:0:ffff]:12345".parse().unwrap();
        let query = Query::query(
            Name::from_ascii("test.apps.example.com").unwrap(),
            RecordType::AAAA,
        );
        let lower_query = LowerQuery::from(query);
        let header = Header::new();
        let request_info = make_request_info(src, &header, &lower_query);

        let result = authority
            .search(request_info, LookupOptions::default())
            .await;
        assert!(matches!(result, LookupControlFlow::Break(Ok(_))));
    }

    #[tokio::test]
    async fn test_search_group_filter_non_matching_returns_refused() {
        let state = DnsState::with_base_domain("apps.example.com");

        state.upsert_app(AppDnsEntry {
            app_id: "app1".to_string(),
            app_name: "test".to_string(),
        });
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m1".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00:0:0:1:aaaa:bbbb:0:1".parse().unwrap(),
            status: "running".to_string(),
            region: "iad".to_string(),
        });
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        let authority = CorrosionAuthority::new(test_config_with_group_filter(), state).unwrap();

        // Source from different group (cccc:dddd)
        let src: SocketAddr = "[fd00:0:0:1:cccc:dddd:0:ffff]:12345".parse().unwrap();
        let query = Query::query(
            Name::from_ascii("test.apps.example.com").unwrap(),
            RecordType::AAAA,
        );
        let lower_query = LowerQuery::from(query);
        let header = Header::new();
        let request_info = make_request_info(src, &header, &lower_query);

        let result = authority
            .search(request_info, LookupOptions::default())
            .await;
        assert!(matches!(
            result,
            LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::Refused)))
        ));
    }

    #[tokio::test]
    async fn test_search_group_filter_ipv4_bypasses_filter() {
        let state = DnsState::with_base_domain("apps.example.com");

        state.upsert_app(AppDnsEntry {
            app_id: "app1".to_string(),
            app_name: "test".to_string(),
        });
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m1".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00:0:0:1:aaaa:bbbb:0:1".parse().unwrap(),
            status: "running".to_string(),
            region: "iad".to_string(),
        });
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        let authority = CorrosionAuthority::new(test_config_with_group_filter(), state).unwrap();

        // IPv4 source bypasses group filter
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let query = Query::query(
            Name::from_ascii("test.apps.example.com").unwrap(),
            RecordType::AAAA,
        );
        let lower_query = LowerQuery::from(query);
        let header = Header::new();
        let request_info = make_request_info(src, &header, &lower_query);

        let result = authority
            .search(request_info, LookupOptions::default())
            .await;
        assert!(matches!(result, LookupControlFlow::Break(Ok(_))));
    }

    #[tokio::test]
    async fn test_search_no_group_filter_returns_all() {
        let state = DnsState::with_base_domain("apps.example.com");

        state.upsert_app(AppDnsEntry {
            app_id: "app1".to_string(),
            app_name: "test".to_string(),
        });
        // Two machines in different groups
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m1".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00:0:0:1:aaaa:bbbb:0:1".parse().unwrap(),
            status: "running".to_string(),
            region: "iad".to_string(),
        });
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m2".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00:0:0:1:cccc:dddd:0:2".parse().unwrap(),
            status: "running".to_string(),
            region: "iad".to_string(),
        });
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        // No group filter — returns all IPs regardless of source
        let authority = CorrosionAuthority::new(test_config(), state).unwrap();

        let src: SocketAddr = "[fd00:0:0:1:aaaa:bbbb:0:ffff]:12345".parse().unwrap();
        let query = Query::query(
            Name::from_ascii("test.apps.example.com").unwrap(),
            RecordType::AAAA,
        );
        let lower_query = LowerQuery::from(query);
        let header = Header::new();
        let request_info = make_request_info(src, &header, &lower_query);

        let result = authority
            .search(request_info, LookupOptions::default())
            .await;
        assert!(matches!(result, LookupControlFlow::Break(Ok(_))));
    }

    #[tokio::test]
    async fn test_search_group_filter_mixed_groups_partial_return() {
        let state = DnsState::with_base_domain("apps.example.com");

        state.upsert_app(AppDnsEntry {
            app_id: "app1".to_string(),
            app_name: "test".to_string(),
        });
        // Machine in group aaaa:bbbb
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m1".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00:0:0:1:aaaa:bbbb:0:1".parse().unwrap(),
            status: "running".to_string(),
            region: "iad".to_string(),
        });
        // Machine in group cccc:dddd
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m2".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00:0:0:1:cccc:dddd:0:2".parse().unwrap(),
            status: "running".to_string(),
            region: "iad".to_string(),
        });
        // Another machine in group aaaa:bbbb
        state.upsert_machine(MachineDnsEntry {
            machine_id: "m3".to_string(),
            app_id: "app1".to_string(),
            ipv6_address: "fd00:0:0:1:aaaa:bbbb:0:3".parse().unwrap(),
            status: "running".to_string(),
            region: "cdg".to_string(),
        });
        state.mark_apps_ready(None);
        state.mark_machines_ready(None);

        let authority = CorrosionAuthority::new(test_config_with_group_filter(), state).unwrap();

        // Source from group aaaa:bbbb — should get m1 and m3, not m2
        let src: SocketAddr = "[fd00:0:0:1:aaaa:bbbb:0:ffff]:12345".parse().unwrap();
        let query = Query::query(
            Name::from_ascii("test.apps.example.com").unwrap(),
            RecordType::AAAA,
        );
        let lower_query = LowerQuery::from(query);
        let header = Header::new();
        let request_info = make_request_info(src, &header, &lower_query);

        let result = authority
            .search(request_info, LookupOptions::default())
            .await;
        assert!(matches!(result, LookupControlFlow::Break(Ok(_))));
    }
}
