use auth_service::g_rpc::jwt::jwt_service_server::JwtServiceServer;
use auth_service::{
    app_state::AppState, g_rpc::GrpcService, services::HashmapUserStore, Application,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server as TonicServer;

pub mod jwt {
    tonic::include_proto!("jwt");
}

#[tokio::main]
async fn main() {
    let app_state = AppState::new(Arc::new(RwLock::new(Box::new(HashmapUserStore::default()))));

    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    let grpc_run = async || {
        let addr = "0.0.0.0:50051";
        println!("listening on {addr}");
        TonicServer::builder()
            .add_service(JwtServiceServer::new(GrpcService))
            .serve(addr.parse().unwrap())
            .await
    };

    tokio::select! {
        _ = app.run() => {},
        _ = grpc_run() => {}
    }
}
