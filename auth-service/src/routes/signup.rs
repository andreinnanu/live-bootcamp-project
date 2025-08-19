use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use secrecy::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User, UserStoreError},
};

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;

    let user = User::new(
        Email::parse(&email).map_err(|_| AuthAPIError::InvalidCredentials)?,
        Password::parse(password).map_err(|_| AuthAPIError::InvalidCredentials)?,
        request.requires_2fa,
    );

    let mut user_store = state.user_store.write().await;

    match user_store.add_user(user).await {
        Ok(()) => {
            let response = Json(SignupResponse {
                message: "User created successfully!".to_string(),
            });

            Ok((StatusCode::CREATED, response))
        }
        Err(UserStoreError::UserAlreadyExists) => Err(AuthAPIError::UserAlreadyExists),
        Err(e) => Err(AuthAPIError::UnexpectedError(e.into())),
    }
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize, PartialEq, Debug, Deserialize)]
pub struct SignupResponse {
    pub message: String,
}
