use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::email::Email, utils::constants::JWT_SECRET};

use super::constants::JWT_COOKIE_NAME;

pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>, GenerateTokenError> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();

    cookie
}

#[derive(Debug)]
pub enum GenerateTokenError {
    TokenError(jsonwebtoken::errors::Error),
    UnexpectedError,
}

pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

fn generate_auth_token(email: &Email) -> Result<String, GenerateTokenError> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .ok_or(GenerateTokenError::UnexpectedError)?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(GenerateTokenError::UnexpectedError)?
        .timestamp();

    let exp: usize = exp
        .try_into()
        .map_err(|_| GenerateTokenError::UnexpectedError)?;

    let sub = email.as_ref().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims).map_err(GenerateTokenError::TokenError)
}

pub async fn validate_token(
    state: &AppState,
    token: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    (!state
        .banned_token_store
        .read()
        .await
        .contains_token(token)
        .await
        .map_err(|_| jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken))?)
    .then_some(())
    .ok_or(jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken))?;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
}

fn create_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::services::{
        HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore, MockEmailClient,
    };

    use super::*;
    use once_cell::sync::Lazy;
    use tokio::sync::RwLock;

    static APP_STATE: Lazy<AppState> = Lazy::new(|| {
        AppState::new(
            Arc::new(RwLock::new(Box::new(HashmapUserStore::default()))),
            Arc::new(RwLock::new(Box::new(HashsetBannedTokenStore::default()))),
            Arc::new(RwLock::new(Box::new(HashmapTwoFACodeStore::default()))),
            Arc::new(RwLock::new(Box::new(MockEmailClient))),
        )
    });

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse("test@example.com").unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse("test@example.com").unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse("test@example.com").unwrap();
        let token = generate_auth_token(&email).unwrap();
        let result = validate_token(&APP_STATE, &token).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();
        let result = validate_token(&APP_STATE, &token).await;
        assert!(result.is_err());
    }
}
