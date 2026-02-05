//! corrosion-dns binary entry point.

use clap::Parser;
use corrosion_dns::{telemetry, Config, DnsServer};
use std::path::PathBuf;
use tracing::{error, info};
use tripwire::Tripwire;

/// Authoritative DNS server backed by Corrosion distributed state.
#[derive(Parser, Debug)]
#[command(name = "corrosion-dns")]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to configuration file (TOML).
    #[arg(short, long, default_value = "corrosion-dns.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load configuration
    let config: Config = config::Config::builder()
        .add_source(config::File::from(args.config.clone()))
        .add_source(
            config::Environment::with_prefix("CORROSION_DNS")
                .separator("__")
                .try_parsing(true),
        )
        .build()?
        .try_deserialize()?;

    // Initialize telemetry
    telemetry::init(&config.telemetry).map_err(|e| e as Box<dyn std::error::Error>)?;

    info!(
        config_file = %args.config.display(),
        listen_addr = %config.dns.listen_addr,
        base_domain = %config.dns.base_domain,
        corrosion_addr = %config.dns.corrosion_addr,
        "Starting corrosion-dns"
    );

    // Setup graceful shutdown
    let (tripwire, tripwire_worker) = Tripwire::new_signals();
    tokio::spawn(tripwire_worker);

    // Run DNS server
    let server = DnsServer::new(config.dns);
    let result = server.run(tripwire).await;

    // Shutdown telemetry
    telemetry::shutdown();

    if let Err(e) = result {
        error!("DNS server error: {}", e);
        return Err(e.into());
    }

    info!("corrosion-dns shutdown complete");
    Ok(())
}
