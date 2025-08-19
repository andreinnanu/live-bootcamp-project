use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, Password, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email = Email::parse(&request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let pwd = Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = &state.user_store.read().await;
    user_store
        .validate_user(email.clone(), pwd)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let user = user_store
        .get_user(email.clone())
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    match user.requires_2fa() {
        true => handle_2fa(user.email(), &state, jar).await,
        false => handle_no_2fa(user.email(), jar).await,
    }
}

#[tracing::instrument(name = "Login handle 2FA", skip_all)]
async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthAPIError> {
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    state
        .two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    state
        .email_client
        .read()
        .await
        .send_email(
            email,
            "Auth Service: 2FA code",
            two_fa_code.clone().as_ref(),
        )
        .await
        .map_err(AuthAPIError::UnexpectedError)?;

    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().to_owned(),
    }));

    Ok((jar, (StatusCode::PARTIAL_CONTENT, response)))
}

#[tracing::instrument(name = "Login handle non 2FA", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthAPIError> {
    let auth_cookie = generate_auth_cookie(email).map_err(AuthAPIError::UnexpectedError)?;
    let updated_jar = jar.add(auth_cookie);
    Ok((
        updated_jar,
        (StatusCode::OK, Json(LoginResponse::RegularAuth)),
    ))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
