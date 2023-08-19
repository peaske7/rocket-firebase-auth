use std::io::Cursor;

use rocket::{
    get,
    http::{ContentType, Status},
    post,
    response,
    routes,
    serde::json::Json,
    Request,
    Response,
    Route,
};
use rocket_firebase_auth::FirebaseToken;
use serde::Serialize;

pub fn routes() -> Vec<Route> {
    routes![verify_token, protected_endpoint]
}

/// The struct we return for success responses (200s)
#[derive(Debug)]
pub struct ApiResponse<T>
where
    T: Serialize,
{
    pub json: Option<Json<T>>,
    pub status: Status,
}

/// Implements the `Responder` trait for Rocket, so we can simply return a for
/// endpoint functions, result and Rocket takes care of the rest.
impl<'r, T: Serialize> response::Responder<'r, 'r> for ApiResponse<T> {
    fn respond_to(self, req: &'r Request) -> response::Result<'r> {
        Response::build_from(self.json.respond_to(req)?)
            .status(self.status)
            .header(ContentType::JSON)
            .ok()
    }
}

/// The struct we return for error responses (400s, 500s)
#[derive(Debug)]
pub struct ApiError {
    pub error: String,
    pub status: Status,
}

/// Implements the `Responder` trait, much like for `ApiResponse`, but for `ApiError`
impl<'a, 'o: 'a> response::Responder<'a, 'o> for ApiError {
    fn respond_to(self, _: &'a Request) -> Result<Response<'o>, Status> {
        Response::build()
            .status(self.status)
            .sized_body(self.error.len(), Cursor::new(self.error))
            .ok()
    }
}

#[derive(Debug, Serialize)]
pub struct VerifyTokenResponse {
    pub uid: String,
}

#[post("/verify")]
async fn verify_token(
    token: FirebaseToken,
) -> ApiResponse<VerifyTokenResponse> {
    ApiResponse {
        json: Some(Json(VerifyTokenResponse { uid: token.sub })),
        status: Status::Ok,
    }
}

#[derive(Debug, Serialize)]
pub struct ProtectedEndpointResponse {
    pub message: String,
}

#[get("/protected")]
async fn protected_endpoint(
    token: FirebaseToken,
) -> ApiResponse<ProtectedEndpointResponse> {
    ApiResponse {
        json: Some(Json(ProtectedEndpointResponse {
            message: format!("Hello, {}! You are signed in!", token.sub),
        })),
        status: Status::Ok,
    }
}
