use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::{HeaderValue, StatusCode};
use std::{collections::HashSet, env, sync::Arc};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::RwLock,
};

const ALLOWED_ORIGINS_VAR_NAME: &str = "ALLOWED_ORIGINS";

#[derive(Debug, Default, Clone)]
pub struct CorsConfig {
    allowed: Arc<RwLock<HashSet<String>>>,
}

impl CorsConfig {
    pub fn new() -> Self {
        let mut allowed = HashSet::default();
        dotenvy::dotenv().ok();
        allowed.extend(
            env::var(ALLOWED_ORIGINS_VAR_NAME)
                .unwrap_or_default()
                .split(',')
                .map(|s| s.to_owned())
                .collect::<Vec<String>>(),
        );
        let str = env::var(ALLOWED_ORIGINS_VAR_NAME).unwrap_or_default();
        println!("ALLOWED_ORIGINS={str}");
        Self {
            allowed: Arc::new(RwLock::new(allowed)),
        }
    }

    pub fn update_allowed_origins_on_sighup(&mut self) {
        let allowed_clone = self.allowed.clone();
        tokio::spawn(async move {
            let mut stream = signal(SignalKind::hangup()).unwrap();

            loop {
                stream.recv().await;
                let mut allowed = allowed_clone.write().await;
                allowed.clear();
                let _ = dotenvy::from_path_override("/app/.env");
                allowed.extend(
                    env::var(ALLOWED_ORIGINS_VAR_NAME)
                        .unwrap_or_default()
                        .split(',')
                        .map(|s| s.to_owned())
                        .collect::<Vec<String>>(),
                );
                let str = env::var(ALLOWED_ORIGINS_VAR_NAME).unwrap_or_default();
                println!("ALLOWED_ORIGINS={str}");
            }
        });
    }

    pub async fn is_allowed(&self, origin: HeaderValue) -> bool {
        let Some(origin_str) = origin.to_str().ok() else {
            return false;
        };

        println!("Origin in request: {origin_str}");

        println!("Origins in list:");
        for origin in self.allowed.read().await.iter() {
            println!("{origin}");
        }

        self.allowed.read().await.contains(origin_str)
    }
}

pub async fn check_allowed_origins(
    State(state): State<CorsConfig>,
    request: Request,
    next: Next,
) -> Response {
    println!("check_allowed_origins");

    if let Some(origin) = request.headers().get("origin") {
        if !state.is_allowed(origin.clone()).await {
            println!("REFUSED BY MY MIDDLEWARE");

            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized: Origin not allowed".into())
                .unwrap();
        }
    }

    next.run(request).await
}
