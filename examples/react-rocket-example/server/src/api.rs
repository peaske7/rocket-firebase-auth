use std::io::Cursor;

use rocket::{
    get,
    http::{ContentType, Status},
    post,
    response,
    routes,
    serde as rocket_serde,
    Request,
    Response,
    Route,
    State,
};
use rocket_firebase_auth::BearerToken;
use serde::Serialize;

use crate::ServerState;

pub fn routes() -> Vec<Route> {
    routes![verify_token, protected_endpoint]
}

/// The struct we return for success responses (200s)
#[derive(Debug)]
pub struct ApiResponse<T> {
    pub json:   Option<rocket_serde::json::Json<T>>,
    pub status: Status,
}

/// Implements the `Responder` trait for Rocket, so we can simply return a for
/// endpoint functions, result and Rocket takes care of the rest.
impl<'r, T: rocket_serde::Serialize> response::Responder<'r, 'r>
    for ApiResponse<T>
{
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
    pub error:  String,
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
    state: &State<ServerState>,
    token: BearerToken,
) -> Result<ApiResponse<VerifyTokenResponse>, ApiError> {
    let token = state.auth.verify(&token).await.map_err(|_| ApiError {
        error:  "Couldn't verify bearer token".to_string(),
        status: Status::Unauthorized,
    })?;

    let response = ApiResponse {
        json:   Some(rocket_serde::json::Json(VerifyTokenResponse {
            uid: token.uid,
        })),
        status: Status::Ok,
    };

    Ok(response)
}

#[derive(Debug, Serialize)]
pub struct ProtectedEndpointResponse {
    pub message: String,
}

#[get("/protected")]
async fn protected_endpoint(
    state: &State<ServerState>,
    token: BearerToken,
) -> Result<ApiResponse<ProtectedEndpointResponse>, ApiError> {
    let token = state.auth.verify(&token).await.ok();

    let message = match token {
        Some(token) => format!("Hello, {}! You are signed in!", token.uid),
        None => "Hello! You are not signed in!".to_string(),
    };

    let response = ApiResponse {
        json:   Some(rocket_serde::json::Json(ProtectedEndpointResponse {
            message,
        })),
        status: Status::Ok,
    };

    Ok(response)
}
