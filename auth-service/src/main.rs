use std::sync::Arc;

use auth_service::{
    app_state::AppState,
    configure_postgresql, configure_redis,
    services::{MockEmailClient, PostgresUserStore, RedisBannedTokenStore, RedisTwoFACodeStore},
    utils::constants::prod,
    Application,
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;
    let redis_conn = Arc::new(RwLock::new(configure_redis()));
    let app_state = AppState::new(
        Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool)))),
        Arc::new(RwLock::new(Box::new(RedisBannedTokenStore::new(
            redis_conn.clone(),
        )))),
        Arc::new(RwLock::new(Box::new(RedisTwoFACodeStore::new(redis_conn)))),
        Arc::new(RwLock::new(Box::new(MockEmailClient))),
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
