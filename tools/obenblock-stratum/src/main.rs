//! obenblock-stratum: configuration from the environment (README.md,
//! "Configuration"), then [`server::StratumServer::run`] until SIGINT/SIGTERM.

use std::process::ExitCode;

use obenblock_stratum::server::{self, StratumServer};

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!("obenblock-stratum {}: Stratum V1 job server for ObenBlock (solo pool).", env!("CARGO_PKG_VERSION"));
        println!("Configured with OBB_STRATUM_* environment variables; see tools/obenblock-stratum/README.md.");
        return ExitCode::SUCCESS;
    }
    let cfg = match server::config_from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = StratumServer::new(cfg).run().await {
        eprintln!("fatal: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
