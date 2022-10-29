//! Bridge with Rocket

use crate::{
    bearer_token::BearerToken,
    errors::{AuthError, InvalidAuthHeader},
};
use rocket::{http::Status, outcome, outcome::IntoOutcome, request, Request};

/// Allows for direct access to bearer tokens as function parameters in rocket
#[rocket::async_trait]
impl<'r> request::FromRequest<'r> for BearerToken {
    type Error = AuthError;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> request::Outcome<Self, Self::Error> {
        match request
            .headers()
            .get("Authorization")
            .collect::<Vec<&str>>()
        {
            auth_field if auth_field.is_empty() => outcome::Outcome::Failure((
                Status::BadRequest,
                AuthError::InvalidAuthHeader(
                    InvalidAuthHeader::MissingAuthHeader,
                ),
            )),
            auth_field if auth_field.len() == 1 => {
                auth_field[0].try_into().into_outcome(Status::BadRequest)
            }
            _ => outcome::Outcome::Failure((
                Status::BadRequest,
                AuthError::InvalidAuthHeader(InvalidAuthHeader::BadCount),
            )),
        }
    }
}
