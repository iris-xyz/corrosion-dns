//! Telemetry setup for corrosion-dns.
//!
//! Supports:
//! - Tracing with configurable log levels
//! - Prometheus metrics endpoint (with `prometheus` feature)
//! - OpenTelemetry tracing export (with `otel` feature)

#[cfg(feature = "prometheus")]
use std::net::SocketAddr;
#[cfg(any(feature = "prometheus", feature = "otel"))]
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::TelemetryConfig;

#[cfg(feature = "otel")]
use std::sync::OnceLock;
#[cfg(feature = "otel")]
static TRACER_PROVIDER: OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> = OnceLock::new();

/// Initialize telemetry (tracing, metrics, optional OTLP).
pub fn init(config: &TelemetryConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing(config)?;

    // Start Prometheus exporter if configured
    #[cfg(feature = "prometheus")]
    if let Some(addr) = config.prometheus_addr {
        start_prometheus_exporter(addr)?;
    }

    Ok(())
}

fn init_tracing(config: &TelemetryConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    #[cfg(feature = "otel")]
    if let Some(ref otel_config) = config.opentelemetry {
        use opentelemetry::KeyValue;
        use opentelemetry_otlp::WithExportConfig;
        use opentelemetry_sdk as otlp_sdk;

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&otel_config.endpoint)
            .build()?;

        let resource = otlp_sdk::Resource::builder()
            .with_attributes([
                KeyValue::new(
                    opentelemetry_semantic_conventions::resource::SERVICE_NAME,
                    otel_config.service_name.clone(),
                ),
                KeyValue::new(
                    opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
                    env!("CARGO_PKG_VERSION"),
                ),
            ])
            .build();

        let provider = otlp_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();

        use opentelemetry::trace::TracerProvider;
        let tracer = provider.tracer("corrosion-dns");

        // Store provider for shutdown
        let _ = TRACER_PROVIDER.set(provider);

        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(otel_layer)
            .init();

        info!(endpoint = %otel_config.endpoint, "OpenTelemetry tracing enabled");
        return Ok(());
    }

    // Default: just fmt layer
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(())
}

/// Start Prometheus metrics HTTP exporter.
#[cfg(feature = "prometheus")]
fn start_prometheus_exporter(
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use metrics_exporter_prometheus::PrometheusBuilder;

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;

    info!(%addr, "Prometheus metrics exporter started");

    Ok(())
}

/// Shutdown telemetry (flush OTLP spans).
pub fn shutdown() {
    #[cfg(feature = "otel")]
    {
        if let Some(provider) = TRACER_PROVIDER.get() {
            if let Err(e) = provider.shutdown() {
                tracing::warn!("Error shutting down tracer provider: {}", e);
            }
        }
    }
}
