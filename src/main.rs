mod args;
mod oracle;

mod utils;

mod handlers;
mod proxy {
    pub mod handler;
    pub mod types;
}

use std::sync::Arc;

use args::Args;
use axum::{
    body::Body,
    http::HeaderValue,
    routing::{get, post},
    Router,
};
use hyper::Method;
use oracle::*;

use clap::Parser;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use stark_vrf::{generate_public_key, StarkVRF};
use tokio::signal;
use tower_http::{cors::{Any, CorsLayer}, trace::TraceLayer};
use tracing::info;

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct ServerState {
    pub args: Args,
    pub client: Client,
    pub vrf: Arc<StarkVRF>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args = Args::parse();

    let secret_key = args.get_secret_key();
    let public_key = generate_public_key(secret_key.parse().unwrap());
    let vrf = Arc::new(StarkVRF::new(public_key).unwrap());

    let client: Client =
        hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(HttpConnector::new());

    let state = ServerState {
        args: args.clone(),
        client,
        vrf,
    };

    let app = Router::new()
        .route("/", get(proxy::handler::proxy_handler))
        .route("/", post(proxy::handler::proxy_handler))
        .route("/info", get(handlers::vrf_info))
        .route("/stark_vrf", post(handlers::stark_vrf))
        .route("/health", get(handlers::health))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin("*".parse::<HeaderValue>().unwrap())
                .allow_headers(Any)
                .allow_methods([Method::GET, Method::POST]),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port))
        .await
        .expect(&format!("Failed to bind to port {}, port already in use by another process. Change the port or terminate the other process.", args.port));

    info!("Server started on http://0.0.0.0:{}", args.port);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
