//! Bridge with Rocket

use crate::{
    errors::{Error, InvalidAuthHeader, InvalidJwt},
    FirebaseAuth, FirebaseToken,
};
use rocket::{
    http::Status,
    request::{self, FromRequest},
    Request,
};

/// Allows for direct access to bearer tokens as function parameters in rocket
/// Try to convert an Authorization headers to a valid bearer token
#[rocket::async_trait]
impl<'r> FromRequest<'r> for FirebaseToken {
    type Error = Error;

    async fn from_request(
        req: &'r Request<'_>,
    ) -> request::Outcome<Self, Self::Error> {
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
                        Some(auth) => match auth.verify(header_content).await {
                            Ok(t) => {
                                // Token is valid
                                let firebase_token = FirebaseToken { ..t };
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
                            }
                        },
                        // FirebaseAuth state not found
                        None => request::Outcome::Failure((
                            Status::InternalServerError,
                            Error::FirebaseAuthStateNotFound,
                        )),
                    }
                }
            }
            None => request::Outcome::Failure((
                Status::Unauthorized,
                Error::InvalidAuthHeader(InvalidAuthHeader::MissingAuthHeader),
            )),
        }
    }
}
