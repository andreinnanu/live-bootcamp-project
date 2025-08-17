use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        Ok(self
            .conn
            .write()
            .await
            .set_ex(get_key(&token), true, TOKEN_TTL_SECONDS as u64)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?)
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let exists: bool = self
            .conn
            .write()
            .await
            .exists(get_key(token))
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(exists)
    }
}

const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{BANNED_TOKEN_KEY_PREFIX}{token}")
}
