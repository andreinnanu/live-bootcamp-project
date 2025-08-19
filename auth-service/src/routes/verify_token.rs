use axum::{extract::State, response::IntoResponse, Json};
use reqwest::StatusCode;
use secrecy::Secret;
use serde::Deserialize;

use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};

#[tracing::instrument(name = "Verify token", skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    validate_token(&state, Secret::new(request.token))
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}
