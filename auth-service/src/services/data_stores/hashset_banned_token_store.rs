use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Clone, Default)]
pub struct HashsetBannedTokenStore {
    store: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>{
        self.store.insert(token);
        Ok(())
    }
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.store.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "TEST_JWT";

    #[tokio::test]
    async fn test_ban_token() {
        let mut hashset_banned_token_store = HashsetBannedTokenStore::default();

        let _ = hashset_banned_token_store.add_token(JWT.to_owned()).await;

        assert_eq!(
            HashSet::from([JWT.to_owned()]),
            hashset_banned_token_store.store
        );
    }

    #[tokio::test]
    async fn test_is_banned() {
        let mut hashset_banned_token_store = HashsetBannedTokenStore::default();

        let _ = hashset_banned_token_store.add_token(JWT.to_owned()).await;

        assert!(hashset_banned_token_store.contains_token(JWT).await.unwrap());
    }
}
