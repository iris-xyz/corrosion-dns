//! Tier 1: Catalog-level integration tests for group filtering.
//!
//! These tests go through Hickory's full `Catalog` → `RequestHandler::handle_request()`
//! → `Authority::search()` → group filter pipeline with crafted source IPs.
//! No root or network privileges required.

mod common;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

// =========================================================================
// Core filtering
// =========================================================================

#[tokio::test]
async fn matching_group_returns_only_same_group() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_a1 = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let ip_a2 = builder.add_machine(&app_id, GROUP_A_HASH, 0x0002, "cdg");
    let _ip_b = builder.add_machine(&app_id, GROUP_B_HASH, 0x0003, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 1).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_a1, ip_a2]);
}

#[tokio::test]
async fn non_matching_group_returns_refused() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_B_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 2).await;

    assert_response_code(&msg, ResponseCode::Refused);
    assert!(extract_aaaa_ips(&msg).is_empty());
}

#[tokio::test]
async fn ipv4_source_bypasses_filter() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_a = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let ip_b = builder.add_machine(&app_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_ipv4_src();
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 3).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_a, ip_b]);
}

#[tokio::test]
async fn ipv4_mapped_ipv6_bypasses_filter() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_a = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let ip_b = builder.add_machine(&app_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_ipv4_mapped_src();
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 4).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_a, ip_b]);
}

#[tokio::test]
async fn no_group_filter_config_returns_all() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_a = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let ip_b = builder.add_machine(&app_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    // No group filter configured
    let catalog = build_catalog(test_dns_config(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 5).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_a, ip_b]);
}

#[tokio::test]
async fn mixed_groups_partial_return() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_a1 = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let _ip_b = builder.add_machine(&app_id, GROUP_B_HASH, 0x0002, "iad");
    let ip_a2 = builder.add_machine(&app_id, GROUP_A_HASH, 0x0003, "cdg");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 6).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_a1, ip_a2]);
}

#[tokio::test]
async fn single_matching_machine() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("api");
    let ip = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "api.apps.example.com", RecordType::AAAA, src, 7).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip]);
}

// =========================================================================
// Edge cases
// =========================================================================

#[tokio::test]
async fn empty_state_nxdomain() {
    let builder = TestStateBuilder::new();
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(
        &catalog,
        "unknown.apps.example.com",
        RecordType::AAAA,
        src,
        8,
    )
    .await;

    assert_response_code(&msg, ResponseCode::NXDomain);
}

#[tokio::test]
async fn state_not_ready_returns_empty() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build_not_ready();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 9).await;

    // NOTE: Our authority returns ServFail via LookupError::ResponseCode(ServFail),
    // but Hickory's Catalog.build_authoritative_response() only handles NXDomain,
    // NameExists, and Refused explicitly — ServFail falls through as NoError with
    // empty answers. This is a known Hickory limitation (see TODO in catalog.rs:579).
    // The important thing is: no AAAA records are leaked.
    assert_response_code(&msg, ResponseCode::NoError);
    assert!(
        extract_aaaa_ips(&msg).is_empty(),
        "expected no AAAA records when state is not ready"
    );
}

#[tokio::test]
async fn group_hash_zero_matches() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip = builder.add_machine(&app_id, 0x0000_0000, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(0x0000_0000, 0xFFFF);
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 10).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip]);
}

#[tokio::test]
async fn group_hash_max_matches() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip = builder.add_machine(&app_id, 0xFFFF_FFFF, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(0xFFFF_FFFF, 0xFFFF);
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 11).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip]);
}

#[tokio::test]
async fn stopped_machines_excluded() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_running = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    builder.add_machine_with_status(&app_id, GROUP_A_HASH, 0x0002, "iad", "stopped");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 12).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_running]);
}

#[tokio::test]
async fn soa_query_unaffected_by_group_filter() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    // Group B source — should still get SOA since it's not AAAA
    let src = make_src(GROUP_B_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "apps.example.com", RecordType::SOA, src, 13).await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert!(!msg.answers().is_empty(), "expected SOA record in answers");
}

// =========================================================================
// Multi-app isolation
// =========================================================================

#[tokio::test]
async fn multiple_apps_own_group_succeeds() {
    let mut builder = TestStateBuilder::new();
    let alpha_id = builder.add_app("alpha");
    let ip_alpha = builder.add_machine(&alpha_id, GROUP_A_HASH, 0x0001, "iad");
    let beta_id = builder.add_app("beta");
    builder.add_machine(&beta_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(
        &catalog,
        "alpha.apps.example.com",
        RecordType::AAAA,
        src,
        14,
    )
    .await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_alpha]);
}

#[tokio::test]
async fn multiple_apps_cross_group_refused() {
    let mut builder = TestStateBuilder::new();
    let alpha_id = builder.add_app("alpha");
    builder.add_machine(&alpha_id, GROUP_A_HASH, 0x0001, "iad");
    let beta_id = builder.add_app("beta");
    builder.add_machine(&beta_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    // Group A queries beta's domain — beta has only group B machines
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(&catalog, "beta.apps.example.com", RecordType::AAAA, src, 15).await;

    assert_response_code(&msg, ResponseCode::Refused);
}

#[tokio::test]
async fn ipv4_sees_all_for_any_app() {
    let mut builder = TestStateBuilder::new();
    let alpha_id = builder.add_app("alpha");
    let ip_a = builder.add_machine(&alpha_id, GROUP_A_HASH, 0x0001, "iad");
    let ip_b = builder.add_machine(&alpha_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_ipv4_src();
    let msg = execute_query(
        &catalog,
        "alpha.apps.example.com",
        RecordType::AAAA,
        src,
        16,
    )
    .await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_a, ip_b]);
}

// =========================================================================
// Regional + group filter
// =========================================================================

#[tokio::test]
async fn regional_query_matching_group() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_iad = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0002, "cdg");
    builder.add_machine(&app_id, GROUP_B_HASH, 0x0003, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_A_HASH, 0xFFFF);
    let msg = execute_query(
        &catalog,
        "iad.web.apps.example.com",
        RecordType::AAAA,
        src,
        17,
    )
    .await;

    assert_response_code(&msg, ResponseCode::NoError);
    assert_aaaa_response(&msg, &[ip_iad]);
}

#[tokio::test]
async fn regional_query_wrong_group_refused() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state);
    let src = make_src(GROUP_B_HASH, 0xFFFF);
    let msg = execute_query(
        &catalog,
        "iad.web.apps.example.com",
        RecordType::AAAA,
        src,
        18,
    )
    .await;

    assert_response_code(&msg, ResponseCode::Refused);
}

// =========================================================================
// Concurrency
// =========================================================================

#[tokio::test]
async fn concurrent_different_groups() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_a = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let ip_b = builder.add_machine(&app_id, GROUP_B_HASH, 0x0002, "iad");
    let state = builder.build();

    let catalog = std::sync::Arc::new(build_catalog(test_dns_config_with_group_filter(), state));

    let mut handles = Vec::new();
    for i in 0..10u16 {
        let catalog = catalog.clone();
        let is_group_a = i % 2 == 0;
        handles.push(tokio::spawn(async move {
            let src = if is_group_a {
                make_src(GROUP_A_HASH, 0xFF00 + i as u32)
            } else {
                make_src(GROUP_B_HASH, 0xFF00 + i as u32)
            };
            let msg = execute_query(
                &catalog,
                "web.apps.example.com",
                RecordType::AAAA,
                src,
                100 + i,
            )
            .await;
            (is_group_a, msg)
        }));
    }

    for handle in handles {
        let (is_group_a, msg) = handle.await.unwrap();
        assert_response_code(&msg, ResponseCode::NoError);
        let ips = extract_aaaa_ips(&msg);
        assert_eq!(ips.len(), 1, "expected exactly 1 IP for each group");
        if is_group_a {
            assert_eq!(ips[0], ip_a);
        } else {
            assert_eq!(ips[0], ip_b);
        }
    }
}

#[tokio::test]
async fn concurrent_same_group() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip1 = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let ip2 = builder.add_machine(&app_id, GROUP_A_HASH, 0x0002, "cdg");
    let state = builder.build();

    let catalog = std::sync::Arc::new(build_catalog(test_dns_config_with_group_filter(), state));

    let mut handles = Vec::new();
    for i in 0..10u16 {
        let catalog = catalog.clone();
        handles.push(tokio::spawn(async move {
            let src = make_src(GROUP_A_HASH, 0xFF00 + i as u32);
            execute_query(
                &catalog,
                "web.apps.example.com",
                RecordType::AAAA,
                src,
                200 + i,
            )
            .await
        }));
    }

    for handle in handles {
        let msg = handle.await.unwrap();
        assert_response_code(&msg, ResponseCode::NoError);
        assert_aaaa_response(&msg, &[ip1, ip2]);
    }
}

// =========================================================================
// State mutation
// =========================================================================

#[tokio::test]
async fn new_machine_visible_after_add() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip1 = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state.clone());
    let src = make_src(GROUP_A_HASH, 0xFFFF);

    // First query: 1 IP
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 21).await;
    assert_aaaa_response(&msg, &[ip1]);

    // Add another machine in same group
    let ip2 = make_ipv6(1, GROUP_A_HASH, 0x0002);
    state.upsert_machine(corrosion_dns::state::MachineDnsEntry {
        machine_id: "m_new".to_string(),
        app_id: "app1".to_string(),
        ipv6_address: ip2,
        status: "running".to_string(),
        region: "cdg".to_string(),
    });

    // Second query: 2 IPs
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 22).await;
    assert_aaaa_response(&msg, &[ip1, ip2]);
}

#[tokio::test]
async fn removed_machine_invisible() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state.clone());
    let src = make_src(GROUP_A_HASH, 0xFFFF);

    // First query: success
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 23).await;
    assert_response_code(&msg, ResponseCode::NoError);

    // Remove the machine
    state.remove_machine("m1");

    // Second query: no machines left → NXDomain
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 24).await;
    assert_response_code(&msg, ResponseCode::NXDomain);
}

#[tokio::test]
async fn cross_group_add_invisible() {
    let mut builder = TestStateBuilder::new();
    let app_id = builder.add_app("web");
    let ip_a = builder.add_machine(&app_id, GROUP_A_HASH, 0x0001, "iad");
    let state = builder.build();

    let catalog = build_catalog(test_dns_config_with_group_filter(), state.clone());
    let src = make_src(GROUP_A_HASH, 0xFFFF);

    // First query: 1 group-A IP
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 25).await;
    assert_aaaa_response(&msg, &[ip_a]);

    // Add a group-B machine
    state.upsert_machine(corrosion_dns::state::MachineDnsEntry {
        machine_id: "m_cross".to_string(),
        app_id: "app1".to_string(),
        ipv6_address: make_ipv6(1, GROUP_B_HASH, 0x0099),
        status: "running".to_string(),
        region: "iad".to_string(),
    });

    // Second query from group A: still only sees group A IP
    let msg = execute_query(&catalog, "web.apps.example.com", RecordType::AAAA, src, 26).await;
    assert_aaaa_response(&msg, &[ip_a]);
}
