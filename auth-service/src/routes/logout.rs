use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthAPIError::MissingToken)?;

    let token = cookie.value().to_owned();

    let _claims = validate_token(&state, &token)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    state
        .banned_token_store
        .write()
        .await
        .add_token(token)
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let jar = jar.remove(Cookie::from(JWT_COOKIE_NAME));

    Ok((jar, StatusCode::OK))
}
