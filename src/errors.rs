#[derive(Debug)]
pub enum AuthError {
    JwtError(String),
    FetchError(String),
    BearerTokenError(BearerTokenErrorReason),
}

#[derive(Debug)]
pub enum BearerTokenErrorReason {
    BadCount,
    Missing,
    Invalid,
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AuthError::JwtError(format!("Auth error occurred: {:?}", e))
    }
}

impl From<reqwest::Error> for AuthError {
    fn from(e: reqwest::Error) -> Self {
        AuthError::FetchError(format!("Auth error occurred: {:?}", e))
    }
}
