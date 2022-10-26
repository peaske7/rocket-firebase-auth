use crate::errors::{AuthError, InvalidAuthHeader};
use rocket::{http::Status, outcome, outcome::IntoOutcome, request, Request};
use std::convert::TryFrom;

/// The bearer token included in request headers
///
/// Valid requests with the `Authorization` header included should look
/// like the following:
/// ```ignore
/// Authorization: Bearer <some_bearer_token>
/// ```
#[derive(Debug)]
pub struct BearerToken(pub String);

/// Try to convert an Authorization headers to a valid bearer token
impl TryFrom<&str> for BearerToken {
    type Error = AuthError;

    fn try_from(header: &str) -> Result<Self, Self::Error> {
        match header.trim().split(' ').collect::<Vec<&str>>() {
            parts if parts[0].to_lowercase() != "bearer" =>
                Err(AuthError::InvalidAuthHeader(
                    InvalidAuthHeader::MissingBearer,
                )),
            parts if parts.len() != 2 =>
                Err(AuthError::InvalidAuthHeader(InvalidAuthHeader::InvalidFormat(
                    "Authorization Header should have 2 arguments formatted as \
                    `Bearer <token>`. Number of arguments did not match the \
                    number of arguments expected.".to_string()
                ))),
            parts if parts[1].len() > 1 =>
                Err(AuthError::InvalidAuthHeader(
                    InvalidAuthHeader::MissingBearerValue,
                )),
            parts  =>
                Ok(BearerToken(parts[1].to_string()))
        }
    }
}

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
