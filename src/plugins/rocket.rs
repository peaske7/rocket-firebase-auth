//! Bridge with Rocket

use crate::{
    errors::{Error, InvalidAuthHeader, InvalidJwt},
    BearerToken, FirebaseAuth, FirebaseToken,
};
use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request,
};

/// Allows for direct access to bearer tokens as function parameters in rocket
#[rocket::async_trait]
impl<'r> FromRequest<'r> for FirebaseToken {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match (
            request
                .headers()
                .get_one("Authorization")
                .and_then(|token| BearerToken::try_from(token).ok()),
            request.rocket().state::<FirebaseAuth>(),
        ) {
            (Some(bearer_token), Some(firebase_auth)) => {
                match firebase_auth.verify(bearer_token.as_str()).await {
                    Ok(firebase_token) => Outcome::Success(firebase_token),
                    Err(_) => Outcome::Error((
                        Status::Unauthorized,
                        Error::InvalidJwt(InvalidJwt::Unspecified),
                    )),
                }
            }
            (Some(_), None) => {
                Outcome::Error((Status::Unauthorized, Error::FirebaseAuthStateNotFound))
            }
            _ => Outcome::Error((
                Status::BadRequest,
                Error::InvalidAuthHeader(InvalidAuthHeader::InvalidFormat(
                    "Failed to parse bearer token.".to_string(),
                )),
            )),
        }
    }
}
