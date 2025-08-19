use std::sync::Arc;

use redis::{Commands, Connection};
use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

use color_eyre::eyre::{Context, Result};

use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    #[tracing::instrument(name = "Creting new RedisBannedTokenStore", skip_all)]
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    #[tracing::instrument(name = "Adding token to banned token store", skip(self))]
    async fn add_token(&mut self, token: Secret<String>) -> Result<()> {
        Ok(self
            .conn
            .write()
            .await
            .set_ex(get_key(token.expose_secret()), true, TOKEN_TTL_SECONDS as u64)
            .wrap_err("failed to set banned token in Redis")
            .map_err(BannedTokenStoreError::UnexpectedError)?)
    }

    #[tracing::instrument(name = "Checking if banned token store contains token", skip(self))]
    async fn contains_token(&self, token: Secret<String>) -> Result<bool> {
        let exists: bool = self
            .conn
            .write()
            .await
            .exists(get_key(token.expose_secret()))
            .wrap_err("failed to check if token exists in Redis")
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        Ok(exists)
    }
}

const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{BANNED_TOKEN_KEY_PREFIX}{token}")
}
