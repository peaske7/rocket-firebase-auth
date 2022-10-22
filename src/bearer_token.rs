use rocket::{request, outcome, Request, http::Status};
use crate::{BearerToken, errors::AuthError::BearerTokenError};

fn get_bearer_token(header: &str) -> BearerToken {
    if header.len() >= 7 {
        BearerToken(header.to_string()[7..].to_string())
    } else {
        BearerToken("".to_string())
    }
}

fn is_valid_header(header: &str) -> bool {
    let parts = header.trim().split(' ').collect::<Vec<&str>>();
    parts.len() == 2 && parts[0] == "Bearer" && parts[1].len() > 1
}

#[rocket::async_trait]
impl<'r> request::FromRequest<'r> for BearerToken {
    type Error = BearerTokenError;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> request::Outcome<Self, Self::Error> {
        let auth_headers = request
            .headers()
            .get("Authorization")
            .collect::<Vec<&str>>();

        match auth_headers.len() {
            0 => outcome::Outcome::Failure((
                Status::BadRequest,
                BearerTokenError::Missing,
            )),
            1 if is_valid_header(auth_headers[0]) => {
                outcome::Outcome::Success(get_bearer_token(auth_headers[0]))
            }
            1 => outcome::Outcome::Failure((
                Status::BadRequest,
                BearerTokenError::Invalid,
            )),
            _ => outcome::Outcome::Failure((
                Status::BadRequest,
                BearerTokenError::BadCount,
            )),
        }
    }
}
