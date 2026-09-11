//! Binary entrypoint: resolve the configuration, build the state, serve.

use tracing::info;

use libid_server_rs::{
    build_state,
    config::Config,
    serve,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::resolve()?;
    // The artifact is retrieved before the listener binds; a failure exits
    // non-zero.
    let state = build_state(&cfg).await?;

    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", cfg.host, cfg.port)).await?;
    info!("libid-server-rs listening on {}", listener.local_addr()?);

    serve(state, listener, async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutting down");
    })
    .await?;
    Ok(())
}
