//! Binary entrypoint: parse config, build state, serve.

use clap::Parser;
use tracing::info;

use libid_server_rs::{
    build_state,
    config::Config,
    routes,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::parse();
    let addr = format!("{}:{}", cfg.host, cfg.port);

    let state = build_state(&cfg)?;
    let app = routes::build_router(&state).with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("libid-server-rs listening on {}", listener.local_addr()?);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutting down");
        })
        .await?;
    Ok(())
}
