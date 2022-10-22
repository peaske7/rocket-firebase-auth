#[derive(Debug)]
pub enum AuthError {
    InvalidJwt(String),
    FetchFailed(String),
    InvalidBearerToken(InvalidReason),
}

#[derive(Debug)]
pub enum InvalidReason {
    BadCount,
    Missing,
    Invalid,
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AuthError::InvalidJwt(format!("Auth error occurred: {:?}", e))
    }
}

impl From<reqwest::Error> for AuthError {
    fn from(e: reqwest::Error) -> Self {
        AuthError::FetchFailed(format!("Auth error occurred: {:?}", e))
    }
}
