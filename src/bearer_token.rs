use crate::{
    errors::{AuthError, InvalidReason},
    BearerToken,
};
use rocket::{http::Status, outcome, request, Request};

fn bearer_token(header: &str) -> BearerToken {
    if header.len() >= 7 {
        BearerToken(header.to_string()[7..].to_string())
    } else {
        BearerToken(String::default())
    }
}

fn is_valid_header(header: &str) -> bool {
    let parts = header.trim().split(' ').collect::<Vec<&str>>();
    parts.len() == 2 && parts[0] == "Bearer" && parts[1].len() > 1
}

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
            ah if ah.is_empty() => outcome::Outcome::Failure((
                Status::BadRequest,
                AuthError::InvalidBearerToken(InvalidReason::Missing),
            )),
            ah if ah.len() == 1 && is_valid_header(ah[0]) => {
                outcome::Outcome::Success(bearer_token(ah[0]))
            }
            ah if ah.len() == 1 => outcome::Outcome::Failure((
                Status::BadRequest,
                AuthError::InvalidBearerToken(InvalidReason::Invalid),
            )),
            _ => outcome::Outcome::Failure((
                Status::BadRequest,
                AuthError::InvalidBearerToken(InvalidReason::BadCount),
            )),
        }
    }
}
