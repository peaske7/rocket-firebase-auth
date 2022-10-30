//! Error management for the library

/// All rocket-firebase-auth errors are consolidated into the following AuthError
#[derive(Debug)]
pub enum AuthError {
    /// Invalid JWT given
    InvalidJwt(InvalidJwt),
    /// Fail to fetch list of JWKs from issuer
    FetchFailed(String),
    /// Invalid Authorization header in request
    InvalidAuthHeader(InvalidAuthHeader),
    /// jsonwebtoken errors
    JsonWebTokenError(String),
    #[cfg(feature = "env")]
    /// Failures related to reading from environment variables
    Env(Env),
}

/// Errors around the contents of a decoded token
#[derive(Debug, Copy, Clone)]
pub enum InvalidJwt {
    /// Kid is missing
    MissingKid,
    /// Jwk for a Kid could not be found
    MatchingJwkNotFound,
}

/// Errors around invalid request headers and encoded tokens
#[derive(Debug)]
pub enum InvalidAuthHeader {
    /// Too many Authorization headers. Expects only 1
    BadCount,
    /// Authorization header is missing altogether in request
    MissingAuthHeader,
    /// `Bearer` keyword is missing
    MissingBearer,
    /// Bearer token is missing
    MissingBearerValue,
    /// Invalid Bearer token format. Couldn't parse to BearerToken type
    InvalidFormat(String),
}

/// Errors that occur when reading environment variables
#[cfg(feature = "env")]
#[derive(Debug)]
pub enum Env {
    /// Invalid Firebase credentials given
    InvalidFirebaseCredentials(String),
    /// Invalid file format received
    InvalidFileFormat(String),
    /// Missing env file
    MissingEnvFile(String),
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AuthError::JsonWebTokenError(format!("Auth error occurred: {e}"))
    }
}

impl From<reqwest::Error> for AuthError {
    fn from(e: reqwest::Error) -> Self {
        AuthError::FetchFailed(format!("Auth error occurred: {e}"))
    }
}
