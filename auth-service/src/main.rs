use std::sync::Arc;

use auth_service::{app_state::AppState, services::HashmapUserStore, Application};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let app_state = AppState::new(Arc::new(RwLock::new(Box::new(HashmapUserStore::default()))));

    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
