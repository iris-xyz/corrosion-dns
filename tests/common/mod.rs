//! Shared test infrastructure for group filter integration tests.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};
use hickory_server::authority::{AuthorityObject, Catalog, MessageRequest, MessageResponse};
use hickory_server::proto::rr::Record;
use hickory_server::proto::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use corrosion_dns::authority::CorrosionAuthority;
use corrosion_dns::config::{DnsConfig, GroupFilterConfig, SoaConfig};
use corrosion_dns::state::{AppDnsEntry, DnsState, MachineDnsEntry};

// --- Constants ---

pub const BASE_DOMAIN: &str = "apps.example.com";
pub const GROUP_A_HASH: u32 = 0xAAAA_BBBB;
pub const GROUP_B_HASH: u32 = 0xCCCC_DDDD;

// --- TestResponseHandler ---

/// Captures the serialized DNS response for inspection in tests.
///
/// Implements `ResponseHandler` so it can be passed to `Catalog::handle_request()`.
/// The response is serialized via `MessageResponse::destructive_emit()` and stored
/// as raw wire-format bytes, which can then be parsed with `Message::from_vec()`.
#[derive(Clone)]
pub struct TestResponseHandler {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl TestResponseHandler {
    pub fn new() -> Self {
        Self {
            buf: Arc::new(Mutex::new(Vec::with_capacity(512))),
        }
    }

    /// Parse the captured wire bytes into a `Message` for assertions.
    pub fn into_message(self) -> Message {
        let buf = self.buf.lock().unwrap();
        assert!(!buf.is_empty(), "no response was captured");
        Message::from_vec(&buf).expect("failed to parse captured DNS response")
    }
}

#[async_trait]
impl ResponseHandler for TestResponseHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut buf = self.buf.lock().unwrap();
        buf.clear();
        let mut encoder = BinEncoder::new(&mut *buf);
        encoder.set_max_size(u16::MAX);
        let info = response
            .destructive_emit(&mut encoder)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(info)
    }
}

// --- IPv6 address helpers ---

/// Build an IPv6 address with the group hash at bits 64-95:
/// `fd00:0:0:NNNN:GG_HI:GG_LO:MM_HI:MM_LO`
pub fn make_ipv6(node: u16, group_hash: u32, machine_suffix: u32) -> Ipv6Addr {
    let g_hi = (group_hash >> 16) as u16;
    let g_lo = (group_hash & 0xFFFF) as u16;
    let m_hi = (machine_suffix >> 16) as u16;
    let m_lo = (machine_suffix & 0xFFFF) as u16;
    Ipv6Addr::new(0xfd00, 0, 0, node, g_hi, g_lo, m_hi, m_lo)
}

/// Build an IPv6 SocketAddr for use as a DNS query source.
pub fn make_src(group_hash: u32, machine_suffix: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(make_ipv6(1, group_hash, machine_suffix)), 12345)
}

/// Build an IPv4 source address (bypasses group filter).
pub fn make_ipv4_src() -> SocketAddr {
    "10.0.0.1:12345".parse().unwrap()
}

/// Build an IPv4-mapped-IPv6 source address (bypasses group filter).
pub fn make_ipv4_mapped_src() -> SocketAddr {
    "[::ffff:10.0.0.1]:12345".parse().unwrap()
}

// --- Config builders ---

pub fn test_dns_config() -> DnsConfig {
    DnsConfig {
        listen_addr: "127.0.0.1:5353".parse().unwrap(),
        base_domain: BASE_DOMAIN.to_string(),
        ttl: 60,
        corrosion_addr: "127.0.0.1:8080".parse().unwrap(),
        soa: SoaConfig::default(),
        group_filter: None,
    }
}

pub fn test_dns_config_with_group_filter() -> DnsConfig {
    DnsConfig {
        group_filter: Some(GroupFilterConfig::default()),
        ..test_dns_config()
    }
}

// --- State builder ---

pub struct TestStateBuilder {
    state: DnsState,
    app_counter: u32,
    machine_counter: u32,
}

impl TestStateBuilder {
    pub fn new() -> Self {
        Self {
            state: DnsState::with_base_domain(BASE_DOMAIN),
            app_counter: 0,
            machine_counter: 0,
        }
    }

    /// Add an app. Returns app_id.
    pub fn add_app(&mut self, app_name: &str) -> String {
        self.app_counter += 1;
        let app_id = format!("app{}", self.app_counter);
        self.state.upsert_app(AppDnsEntry {
            app_id: app_id.clone(),
            app_name: app_name.to_string(),
        });
        app_id
    }

    /// Add a running machine. Returns its IPv6 address.
    pub fn add_machine(
        &mut self,
        app_id: &str,
        group_hash: u32,
        machine_suffix: u32,
        region: &str,
    ) -> Ipv6Addr {
        self.add_machine_with_status(app_id, group_hash, machine_suffix, region, "running")
    }

    /// Add a machine with a custom status. Returns its IPv6 address.
    pub fn add_machine_with_status(
        &mut self,
        app_id: &str,
        group_hash: u32,
        machine_suffix: u32,
        region: &str,
        status: &str,
    ) -> Ipv6Addr {
        self.machine_counter += 1;
        let ip = make_ipv6(1, group_hash, machine_suffix);
        self.state.upsert_machine(MachineDnsEntry {
            machine_id: format!("m{}", self.machine_counter),
            app_id: app_id.to_string(),
            ipv6_address: ip,
            status: status.to_string(),
            region: region.to_string(),
        });
        ip
    }

    /// Mark state as ready and return it.
    pub fn build(self) -> DnsState {
        self.state.mark_apps_ready(None);
        self.state.mark_machines_ready(None);
        self.state
    }

    /// Return state WITHOUT marking ready.
    pub fn build_not_ready(self) -> DnsState {
        self.state
    }
}

// --- Query/Request construction ---

/// Build wire-format bytes for a DNS query.
pub fn build_query_bytes(name: &str, record_type: RecordType, id: u16) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_ascii(name).unwrap());
    query.set_query_type(record_type);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);
    msg.to_vec().unwrap()
}

/// Parse wire bytes into a MessageRequest.
pub fn parse_message_request(bytes: &[u8]) -> MessageRequest {
    let mut decoder = BinDecoder::new(bytes);
    MessageRequest::read(&mut decoder).expect("failed to parse MessageRequest")
}

/// Build a full `Request` with a crafted source address.
pub fn build_request(name: &str, record_type: RecordType, src: SocketAddr, id: u16) -> Request {
    let bytes = build_query_bytes(name, record_type, id);
    let msg = parse_message_request(&bytes);
    Request::new(msg, src, Protocol::Udp)
}

/// Build a Catalog with a CorrosionAuthority.
pub fn build_catalog(config: DnsConfig, state: DnsState) -> Catalog {
    let authority =
        CorrosionAuthority::new(config, state).expect("failed to create CorrosionAuthority");
    let origin = authority.origin().clone();
    let authority: Arc<dyn AuthorityObject> = Arc::new(authority);
    let mut catalog = Catalog::new();
    catalog.upsert(origin, vec![authority]);
    catalog
}

// --- Response helpers ---

/// Execute a query through the catalog and return the parsed response.
pub async fn execute_query(
    catalog: &Catalog,
    name: &str,
    record_type: RecordType,
    src: SocketAddr,
    id: u16,
) -> Message {
    let request = build_request(name, record_type, src, id);
    let handler = TestResponseHandler::new();
    catalog.handle_request(&request, handler.clone()).await;
    handler.into_message()
}

/// Extract AAAA addresses from a response.
pub fn extract_aaaa_ips(msg: &Message) -> Vec<Ipv6Addr> {
    msg.answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::AAAA(aaaa) => Some(Ipv6Addr::from(*aaaa)),
            _ => None,
        })
        .collect()
}

/// Assert response code.
pub fn assert_response_code(msg: &Message, expected: ResponseCode) {
    assert_eq!(
        msg.response_code(),
        expected,
        "expected {:?}, got {:?}",
        expected,
        msg.response_code()
    );
}

/// Assert response is successful with exactly the expected IPs.
pub fn assert_aaaa_response(msg: &Message, expected_ips: &[Ipv6Addr]) {
    assert_response_code(msg, ResponseCode::NoError);
    let mut actual = extract_aaaa_ips(msg);
    actual.sort();
    let mut expected: Vec<Ipv6Addr> = expected_ips.to_vec();
    expected.sort();
    assert_eq!(
        actual, expected,
        "AAAA records mismatch.\nactual:   {:?}\nexpected: {:?}",
        actual, expected
    );
}
