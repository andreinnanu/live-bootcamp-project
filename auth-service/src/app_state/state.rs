use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::{BannedTokenStore, UserStore};

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<Box<dyn UserStore + 'static>>>;
pub type BannedTokenStoreType = Arc<RwLock<Box<dyn BannedTokenStore + 'static>>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
    pub banned_token_store: BannedTokenStoreType,
}

impl AppState {
    pub fn new(user_store: UserStoreType, banned_token_store: BannedTokenStoreType) -> Self {
        Self {
            user_store,
            banned_token_store,
        }
    }
}
