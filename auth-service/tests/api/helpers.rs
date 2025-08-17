use std::{str::FromStr, sync::Arc};

use auth_service::{
    app_state::{AppState, TwoFACodeStoreType},
    configure_redis, get_postgres_pool,
    services::{MockEmailClient, PostgresUserStore, RedisBannedTokenStore, RedisTwoFACodeStore},
    utils::constants::{test, DATABASE_URL},
    Application,
};
use reqwest::cookie::Jar;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    Connection, Executor, PgConnection, PgPool,
};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
    pub cookie_jar: Arc<Jar>,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub db_name: String,
    pub cleanup_called: bool,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.cleanup_called {
            panic!("Test DB was not deleted");
        }
    }
}

impl TestApp {
    pub async fn new() -> Self {
        let (pg_pool, db_name) = configure_postgresql().await;
        let redis_conn = Arc::new(RwLock::new(configure_redis()));
        let two_fa_code_store: TwoFACodeStoreType = Arc::new(RwLock::new(Box::new(
            RedisTwoFACodeStore::new(redis_conn.clone()),
        )));
        let app_state = AppState::new(
            Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool)))),
            Arc::new(RwLock::new(Box::new(RedisBannedTokenStore::new(
                redis_conn.clone(),
            )))),
            two_fa_code_store.clone(),
            Arc::new(RwLock::new(Box::new(MockEmailClient))),
        );

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        Self {
            address,
            http_client,
            cookie_jar,
            two_fa_code_store: two_fa_code_store.clone(),
            db_name,
            cleanup_called: false,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn create_user_and_login(
        &self,
        email: &str,
        pwd: &str,
        two_fa: bool,
    ) -> reqwest::Response {
        let mut response = self
            .post_signup(&serde_json::json!({
                "email": email,
                "password": pwd,
                "requires2FA": two_fa
            }))
            .await;

        assert_eq!(response.status().as_u16(), 201);

        let login_body = serde_json::json!({
            "email": email,
            "password": pwd,
        });

        response = self.post_login(&login_body).await;
        response
    }

    pub async fn cleanup(&mut self) {
        delete_database(&self.db_name).await;
        self.cleanup_called = true;
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql() -> (PgPool, String) {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    let db_name = Uuid::new_v4().to_string();

    configure_database(&postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = format!("{postgresql_conn_url}/{db_name}");

    let pg_pool = get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!");
    (pg_pool, db_name)
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    connection
        .execute(format!(r#"CREATE DATABASE "{db_name}";"#).as_str())
        .await
        .expect("Failed to create database.");

    let db_conn_string = format!("{db_conn_string}/{db_name}");

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url: String = DATABASE_URL.to_owned();

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{db_name}'
                  AND pid <> pg_backend_pid();
        "#
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    connection
        .execute(format!(r#"DROP DATABASE "{db_name}";"#).as_str())
        .await
        .expect("Failed to drop the database.");
}
