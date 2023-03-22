//! Extracting bearer tokens from request headers
//! and with the assumption that they're Firebase JWTs, checking
//! their validity.

use crate::{errors::{Error, InvalidAuthHeader, InvalidJwt}, DecodedToken, FirebaseAuth};
use rocket::{request::{Request, FromRequest, self}, http::Status};

/// The bearer token included in request headers
///
/// Valid requests with the `Authorization` header included should look
/// like the following:
/// ```ignore
/// Authorization: Bearer <some_bearer_token>
/// ```
#[derive(Debug)]
pub struct FirebaseToken {
    // The JWT token with all its claims
    pub token: DecodedToken,
}

/// Try to convert an Authorization headers to a valid bearer token
#[rocket::async_trait]
impl<'r> FromRequest<'r> for FirebaseToken {
    type Error = Error;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Is header present?
        match req.headers().get_one("Authorization") {
            Some(header_raw) => {
                let (header_name, header_content) = header_raw.split_at(7);
                // Is header in the correct format?
                if header_name != "Bearer " {
                    request::Outcome::Failure((
                        Status::Unauthorized,
                        Error::InvalidAuthHeader(InvalidAuthHeader::InvalidFormat(
                            "Authorization Header should have 2 arguments formatted as \
                            `Bearer <token>`. Number of arguments did not match the \
                            number of arguments expected.".to_string())
                        ),
                    ))
                } else {
                    // Find the FirebaseAuth state
                    match req.rocket().state::<FirebaseAuth>() {
                        // Verify if the token is valid
                        Some(auth) => match auth.verify_token(header_content).await {
                            Ok(t) => {
                                // Token is valid
                                let firebase_token = FirebaseToken { token: t };
                                request::Outcome::Success(firebase_token)
                            }
                            Err(_) => {
                                // TODO: Find a way to convert `e` into InvalidJwt error type
                                // and replace `InvalidJwt::Unspecified` with it
                                request::Outcome::Failure((
                                    // Token is invalid
                                    Status::Unauthorized,
                                    Error::InvalidJwt(InvalidJwt::Unspecified),
                                ))
                            },
                        },
                        // FirebaseAuth state not found
                        None => request::Outcome::Failure((
                            Status::InternalServerError,
                            Error::FirebaseAuthStateNotFound,
                        )),
                    }
                }
            }
            None => request::Outcome::Failure((Status::Unauthorized, Error::InvalidAuthHeader(InvalidAuthHeader::MissingAuthHeader))),
        }
    }
}
