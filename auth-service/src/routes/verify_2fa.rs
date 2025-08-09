use axum::{extract::State, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email = Email::parse(&request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    let two_fa_code =
        TwoFACode::parse(request.two_fa_code).map_err(|_| AuthAPIError::InvalidCredentials)?;

    {
        let mut two_fa_code_store = state.two_fa_code_store.write().await;
        let (stored_login_attempt_id, stored_two_fa_code) = two_fa_code_store
            .get_code(&email)
            .await
            .map_err(|_| AuthAPIError::IncorrectCredentials)?;

        two_fa_code_store
            .remove_code(&email)
            .await
            .map_err(|_| AuthAPIError::UnexpectedError)?;

        if stored_login_attempt_id != login_attempt_id || stored_two_fa_code != two_fa_code {
            return Err(AuthAPIError::IncorrectCredentials);
        }
    }

    let auth_cookie = generate_auth_cookie(&email).map_err(|_| AuthAPIError::UnexpectedError)?;
    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK.into_response()))
}

#[derive(Serialize, Deserialize)]
pub struct Verify2FARequest {
    email: String,
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,
    #[serde(rename = "2FACode")]
    two_fa_code: String,
}
