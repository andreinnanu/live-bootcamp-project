use std::sync::Arc;

use auth_service::{
    app_state::AppState,
    services::{HashmapTwoFACodeStore, HashmapUserStore, HashsetBannedTokenStore, MockEmailClient},
    utils::constants::prod,
    Application,
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let app_state = AppState::new(
        Arc::new(RwLock::new(Box::new(HashmapUserStore::default()))),
        Arc::new(RwLock::new(Box::new(HashsetBannedTokenStore::default()))),
        Arc::new(RwLock::new(Box::new(HashmapTwoFACodeStore::default()))),
        Arc::new(RwLock::new(Box::new(MockEmailClient))),
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
