use axum::{extract::Json, http::StatusCode, routing::post, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::{error, info};

#[derive(Debug, Deserialize)]
struct WakeRequest {
    /// The FCM or APNs device token to wake.
    device_token: String,
    /// The platform (e.g., "android", "ios").
    platform: String,
}

#[derive(Serialize)]
struct WakeResponse {
    status: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    info!("Zero Protocol - FCM/APNs Silent Wake Server starting...");

    let app = Router::new().route("/wake", post(handle_wake_request));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3030));
    info!("Push server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_wake_request(Json(payload): Json<WakeRequest>) -> (StatusCode, Json<WakeResponse>) {
    info!(
        "Received wake request for platform: {} (token: {}...)",
        payload.platform,
        &payload.device_token[..8]
    );

    // In a real implementation, you would integrate the Firebase Admin SDK or an APNs client here.
    // This server's job is purely to send a data-only "silent" push notification.
    // Data-only pushes wake the mobile app in the background without showing a UI alert,
    // allowing it to re-connect to the DHT and retrieve any pending messages.

    // Mocking the push delivery success:
    let success = true;

    if success {
        info!(
            "Successfully dispatched silent push to {}",
            payload.platform
        );
        (
            StatusCode::OK,
            Json(WakeResponse {
                status: "dispatched".to_string(),
            }),
        )
    } else {
        error!("Failed to dispatch push notification");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(WakeResponse {
                status: "failed".to_string(),
            }),
        )
    }
}
