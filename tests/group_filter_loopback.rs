//! Tier 2: Real UDP loopback integration tests for group filtering.
//!
//! These tests add IPv6 addresses to the loopback interface, start a real
//! `ServerFuture`, and send real UDP DNS queries from those addresses to
//! verify end-to-end group isolation.
//!
//! **Requires:**
//! - Linux with `ip` command
//! - Root/CAP_NET_ADMIN (or run via Docker with `--privileged`)
//! - Feature flag: `integration-loopback`
//!
//! Run with:
//! ```sh
//! sudo cargo test --test group_filter_loopback --features integration-loopback -- --test-threads=1
//! ```

#![cfg(feature = "integration-loopback")]

mod common;

use std::net::{Ipv6Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use hickory_server::authority::Catalog;
use hickory_server::ServerFuture;
use tokio::net::UdpSocket;

use common::*;

// =========================================================================
// Infrastructure
// =========================================================================

/// RAII guard that adds an IPv6 address to `lo` on creation and removes it on drop.
struct LoopbackGuard {
    addr: Ipv6Addr,
}

impl LoopbackGuard {
    fn new(addr: Ipv6Addr) -> Self {
        let addr_str = format!("{}/128", addr);
        let status = Command::new("ip")
            .args(["addr", "add", &addr_str, "dev", "lo"])
            .status()
            .expect("failed to run `ip addr add`");
        assert!(
            status.success(),
            "ip addr add {} dev lo failed (are you root?)",
            addr_str
        );
        Self { addr }
    }
}

impl Drop for LoopbackGuard {
    fn drop(&mut self) {
        let addr_str = format!("{}/128", self.addr);
        let _ = Command::new("ip")
            .args(["addr", "del", &addr_str, "dev", "lo"])
            .status();
    }
}

/// A test DNS server running on a random port.
struct TestServer {
    port: u16,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    async fn start(catalog: Catalog) -> Self {
        let udp_socket = UdpSocket::bind("[::]:0")
            .await
            .expect("failed to bind UDP socket");
        let port = udp_socket
            .local_addr()
            .expect("failed to get local addr")
            .port();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let mut server = ServerFuture::new(catalog);
            server.register_socket(udp_socket);

            tokio::select! {
                result = server.block_until_done() => {
                    if let Err(e) = result {
                        eprintln!("server error: {}", e);
                    }
                }
                _ = rx => {}
            }
        });

        // Give the server a moment to start accepting packets.
        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            port,
            _shutdown: tx,
        }
    }
}

/// Send a DNS query from a specific source address and return the parsed response.
async fn query_from(
    src: SocketAddr,
    server_port: u16,
    name: &str,
    record_type: RecordType,
    id: u16,
) -> Message {
    let sock = UdpSocket::bind(src)
        .await
        .unwrap_or_else(|e| panic!("failed to bind to {}: {}", src, e));

    let dest: SocketAddr = format!("[::1]:{}", server_port).parse().unwrap();
    let query_bytes = build_query_bytes(name, record_type, id);

    sock.send_to(&query_bytes, dest)
        .await
        .expect("failed to send query");

    let mut buf = vec![0u8; 4096];
    let timeout = Duration::from_secs(5);
    let len = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .expect("query timed out")
        .expect("failed to recv response");

    Message::from_vec(&buf[..len]).expect("failed to parse DNS response")
}

// =========================================================================
// Tests
// =========================================================================

#[tokio::test]
async fn loopback_matching_group() {
    // Client and machine in same group (A)
    let client_addr = make_ipv6(0, GROUP_A_HASH, 0x0100);
    let machine_addr = make_ipv6(1, GROUP_A_HASH, 0x0001);
    let _guard_client = LoopbackGuard::new(client_addr);

    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let server = TestServer::start(catalog).await;

    let src: SocketAddr = SocketAddr::new(client_addr.into(), 0);
    let msg = query_from(
        src,
        server.port,
        "web.apps.example.com",
        RecordType::AAAA,
        1,
    )
    .await;

    assert_response_code(&msg, hickory_proto::op::ResponseCode::NoError);
    assert_aaaa_response(&msg, &[machine_addr]);
}

#[tokio::test]
async fn loopback_non_matching_refused() {
    // Client in group B, machine only in group A
    let client_addr = make_ipv6(0, GROUP_B_HASH, 0x0100);
    let _guard_client = LoopbackGuard::new(client_addr);

    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let server = TestServer::start(catalog).await;

    let src: SocketAddr = SocketAddr::new(client_addr.into(), 0);
    let msg = query_from(
        src,
        server.port,
        "web.apps.example.com",
        RecordType::AAAA,
        2,
    )
    .await;

    assert_response_code(&msg, hickory_proto::op::ResponseCode::Refused);
    assert!(extract_aaaa_ips(&msg).is_empty());
}

#[tokio::test]
async fn loopback_full_isolation() {
    // Client A and client B each see only their own group's machines
    let client_a_addr = make_ipv6(0, GROUP_A_HASH, 0x0100);
    let client_b_addr = make_ipv6(0, GROUP_B_HASH, 0x0200);
    let machine_a_addr = make_ipv6(1, GROUP_A_HASH, 0x0001);
    let machine_b_addr = make_ipv6(1, GROUP_B_HASH, 0x0002);

    let _guard_a = LoopbackGuard::new(client_a_addr);
    let _guard_b = LoopbackGuard::new(client_b_addr);

    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    builder.add_machine(&app_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let server = TestServer::start(catalog).await;

    // Client A sees only machine A
    let src_a: SocketAddr = SocketAddr::new(client_a_addr.into(), 0);
    let msg_a = query_from(
        src_a,
        server.port,
        "web.apps.example.com",
        RecordType::AAAA,
        3,
    )
    .await;
    assert_response_code(&msg_a, hickory_proto::op::ResponseCode::NoError);
    assert_aaaa_response(&msg_a, &[machine_a_addr]);

    // Client B sees only machine B
    let src_b: SocketAddr = SocketAddr::new(client_b_addr.into(), 0);
    let msg_b = query_from(
        src_b,
        server.port,
        "web.apps.example.com",
        RecordType::AAAA,
        4,
    )
    .await;
    assert_response_code(&msg_b, hickory_proto::op::ResponseCode::NoError);
    assert_aaaa_response(&msg_b, &[machine_b_addr]);
}

#[tokio::test]
async fn loopback_ipv4_bypass() {
    // IPv4 client bypasses group filter, sees all machines
    let machine_a_addr = make_ipv6(1, GROUP_A_HASH, 0x0001);
    let machine_b_addr = make_ipv6(1, GROUP_B_HASH, 0x0002);

    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    builder.add_machine(&app_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let server = TestServer::start(catalog).await;

    // Query from IPv4 loopback (port 0 = OS picks)
    let src: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let msg = query_from(
        src,
        server.port,
        "web.apps.example.com",
        RecordType::AAAA,
        5,
    )
    .await;

    assert_response_code(&msg, hickory_proto::op::ResponseCode::NoError);
    assert_aaaa_response(&msg, &[machine_a_addr, machine_b_addr]);
}
