use std::collections::HashSet;

use color_eyre::eyre::Result;
use secrecy::{ExposeSecret, Secret};

use crate::domain::BannedTokenStore;

#[derive(Clone, Default)]
pub struct HashsetBannedTokenStore {
    store: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<()> {
        self.store.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn contains_token(&self, token: Secret<String>) -> Result<bool> {
        Ok(self.store.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "TEST_JWT";

    #[tokio::test]
    async fn test_ban_token() {
        let mut hashset_banned_token_store = HashsetBannedTokenStore::default();

        let _ = hashset_banned_token_store.add_token(Secret::new(JWT.to_owned())).await;

        assert_eq!(
            HashSet::from([JWT.to_owned()]),
            hashset_banned_token_store.store
        );
    }

    #[tokio::test]
    async fn test_is_banned() {
        let mut hashset_banned_token_store = HashsetBannedTokenStore::default();

        let _ = hashset_banned_token_store.add_token(Secret::new(JWT.to_owned())).await;

        assert!(hashset_banned_token_store
            .contains_token(Secret::new(JWT.to_owned()))
            .await
            .unwrap());
    }
}
