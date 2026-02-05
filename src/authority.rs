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
use std::net::Ipv6Addr;
use std::sync::Arc;
use tracing::{debug, trace};

use crate::config::DnsConfig;
use crate::metrics::{self, QueryResult, Timer};
use crate::state::DnsState;

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
    use crate::config::SoaConfig;
    use crate::state::{AppDnsEntry, MachineDnsEntry};

    fn test_config() -> DnsConfig {
        DnsConfig {
            listen_addr: "127.0.0.1:5353".parse().unwrap(),
            base_domain: "apps.example.com".to_string(),
            ttl: 60,
            corrosion_addr: "127.0.0.1:8080".parse().unwrap(),
            soa: SoaConfig::default(),
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
}
