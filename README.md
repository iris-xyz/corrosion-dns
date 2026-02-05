# corrosion-dns

An authoritative DNS server backed by [Corrosion](https://github.com/superfly/corrosion) distributed state. It subscribes to the `apps` and `machines` tables in a Corrosion cluster and serves real-time AAAA records based on running machine IPv6 addresses.

## Architecture

![Architecture](assets/architecture.png)

<details>
<summary>Mermaid source</summary>

See [`assets/architecture.mmd`](assets/architecture.mmd)
</details>

## Motivation

Platforms that host internal services on a private network need internal DNS so services can discover each other by name. The typical solution is a shared DNS server like [CoreDNS](https://coredns.io/) — you deploy one instance and every group on the cluster shares it. This works until you need **true isolation** between groups (tenants, teams, environments). A single CoreDNS cannot isolate per namespace: every group can potentially resolve names belonging to other groups, and a misconfiguration in one affects all of them.

corrosion-dns takes a different approach. You deploy **N instances for N isolated groups**, each with its own configuration and its own view of the world. Each instance derives DNS records directly from its group's [Corrosion](https://github.com/superfly/corrosion) distributed SQLite state — you write to the `apps` and `machines` tables and corrosion-dns picks up the changes in real time. No zone files, no shared state, no record management. Every group gets a fully independent DNS server that only knows about its own services, making isolation the default rather than something bolted on after the fact.

This makes it a good fit for:

- Multi-tenant platforms where each tenant needs its own isolated DNS namespace
- Internal service discovery within private networks
- Edge/regional deployments where machines come and go frequently
- Any system where DNS records should reflect the live state of running infrastructure and groups must not leak into each other

## Features

- Real-time DNS updates via Corrosion subscriptions
- AAAA records for app domains pointing to running machine IPv6 addresses
- Regional DNS lookups (`<region>.<app>.apps.example.com`)
- Automatic reconnection with exponential backoff
- Graceful shutdown support
- Prometheus metrics and optional OpenTelemetry tracing

## Quickstart

### Prerequisites

- Rust 1.75+ (2021 edition)
- A running [Corrosion](https://github.com/superfly/corrosion) agent with `apps` and `machines` tables

### Build and run

```bash
cargo build --release
./target/release/corrosion-dns --config corrosion-dns.example.toml
```

### With Docker

```bash
docker build -t corrosion-dns .
docker run -p 5353:5353/udp -p 5353:5353/tcp -p 9090:9090 \
  -v /path/to/config.toml:/etc/corrosion-dns/config.toml:ro \
  corrosion-dns
```

### With Docker Compose

The included `docker-compose.yml` brings up corrosion-dns alongside a Corrosion agent, with optional Jaeger and Prometheus/Grafana stacks:

```bash
# Core stack (Corrosion + DNS)
docker compose up

# With OpenTelemetry tracing
docker compose --profile otel up

# With Prometheus + Grafana monitoring
docker compose --profile monitoring up
```

## Configuration

corrosion-dns loads configuration from a TOML file and environment variables. Environment variables use the prefix `CORROSION_DNS__` with `__` as separator (e.g., `CORROSION_DNS__DNS__LISTEN_ADDR`).

See [`corrosion-dns.example.toml`](corrosion-dns.example.toml) for a fully commented example.

### Reference

| Key | Default | Description |
|-----|---------|-------------|
| `dns.listen_addr` | *(required)* | Address for DNS queries (UDP + TCP) |
| `dns.base_domain` | *(required)* | Base domain for apps (e.g., `apps.example.com`) |
| `dns.corrosion_addr` | *(required)* | Corrosion API address |
| `dns.ttl` | `60` | TTL for DNS records (seconds) |
| `dns.soa.mname` | `ns1.example.com` | Primary nameserver hostname |
| `dns.soa.rname` | `admin.example.com` | Admin email in DNS format |
| `dns.soa.refresh` | `3600` | SOA refresh interval (seconds) |
| `dns.soa.retry` | `600` | SOA retry interval (seconds) |
| `dns.soa.expire` | `604800` | SOA expire time (seconds) |
| `dns.soa.minimum` | `60` | SOA negative cache TTL (seconds) |
| `telemetry.log_level` | `info` | Log level filter (supports `RUST_LOG` syntax) |
| `telemetry.prometheus_addr` | *(disabled)* | Prometheus metrics endpoint address |
| `telemetry.opentelemetry.endpoint` | *(disabled)* | OTLP gRPC endpoint |
| `telemetry.opentelemetry.service_name` | `corrosion-dns` | Service name for traces |

## Development

```bash
# Run unit tests
cargo test --lib

# Run with clippy lints
cargo clippy --all-features -- -D warnings

# Check formatting
cargo fmt -- --check
```

### Cargo features

| Feature | Default | Description |
|---------|---------|-------------|
| `prometheus` | yes | Prometheus metrics exporter |
| `otel` | no | OpenTelemetry tracing via OTLP |

## Observability

### Metrics

All metrics are prefixed with `corro_dns.`. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `corro_dns.query.count` | Counter | DNS queries by `type` and `result` |
| `corro_dns.query.duration.seconds` | Histogram | Query latency by `type` |
| `corro_dns.query.aaaa.ips_returned` | Histogram | IPs returned per AAAA lookup |
| `corro_dns.state.apps.count` | Gauge | Number of tracked apps |
| `corro_dns.state.machines.count` | Gauge | Number of tracked machines |
| `corro_dns.state.machines.running` | Gauge | Running machines |
| `corro_dns.state.apps_ready` | Gauge | Apps subscription synced (0/1) |
| `corro_dns.state.machines_ready` | Gauge | Machines subscription synced (0/1) |
| `corro_dns.subscription.reconnect.count` | Counter | Subscription reconnects by `reason` |
| `corro_dns.state.resync.count` | Counter | Full state resyncs (missed changes) |

### Logging

Structured logging via `tracing`. Set the level with `telemetry.log_level` in config or the `RUST_LOG` environment variable.

## License

MIT
