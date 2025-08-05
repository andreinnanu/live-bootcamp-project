use std::collections::HashSet;

use crate::domain::BannedTokenStore;

#[derive(Clone, Default)]
pub struct HashsetBannedTokenStore {
    store: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn ban_token(&mut self, token: String) {
        self.store.insert(token);
    }
    async fn is_banned(&self, token: &str) -> bool {
        self.store.contains(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "TEST_JWT";

    #[tokio::test]
    async fn test_ban_token() {
        let mut hashset_banned_token_store = HashsetBannedTokenStore::default();

        hashset_banned_token_store.ban_token(JWT.to_owned()).await;

        assert_eq!(
            HashSet::from([JWT.to_owned()]),
            hashset_banned_token_store.store
        );
    }

    #[tokio::test]
    async fn test_is_banned() {
        let mut hashset_banned_token_store = HashsetBannedTokenStore::default();

        hashset_banned_token_store.ban_token(JWT.to_owned()).await;

        assert!(hashset_banned_token_store.is_banned(JWT).await);
    }
}
