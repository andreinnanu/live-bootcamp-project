use tonic::Response;

use crate::g_rpc::jwt::{VerifyJwtRequest, VerifyJwtResponse};

pub mod jwt {
    tonic::include_proto!("jwt");
}

#[derive(Default)]
pub struct GrpcService;

#[tonic::async_trait]
impl jwt::jwt_service_server::JwtService for GrpcService {
    async fn verify_jwt(
        &self,
        _request: tonic::Request<VerifyJwtRequest>,
    ) -> std::result::Result<
        tonic::Response<VerifyJwtResponse>,
        tonic::Status,
    > {
        Ok(Response::new(jwt::VerifyJwtResponse {
            success: true,
            message: "Success".to_owned()
        }))
    }
}