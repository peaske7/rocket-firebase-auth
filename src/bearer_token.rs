//! Extracting bearer tokens from request headers

use crate::errors::{Error, InvalidAuthHeader};
use std::convert::TryFrom;

/// The bearer token included in request headers
///
/// Valid requests with the `Authorization` header included should look
/// like the following:
/// ```ignore
/// Authorization: Bearer <some_bearer_token>
/// ```
#[derive(Debug)]
pub struct BearerToken(String);

impl BearerToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Try to convert an Authorization headers to a valid bearer token
impl TryFrom<&str> for BearerToken {
    type Error = Error;

    fn try_from(header: &str) -> Result<Self, Self::Error> {
        match header.trim().split(' ').collect::<Vec<&str>>() {
            parts if parts[0].to_lowercase() != "bearer" => {
                Err(Error::InvalidAuthHeader(InvalidAuthHeader::MissingBearer))
            }
            parts if parts.len() != 2 => {
                Err(Error::InvalidAuthHeader(InvalidAuthHeader::InvalidFormat(
                    "Authorization Header had invalid number of arguments."
                        .to_string(),
                )))
            }
            parts if parts[1].is_empty() => Err(Error::InvalidAuthHeader(
                InvalidAuthHeader::MissingBearerValue,
            )),
            parts => Ok(BearerToken(parts[1].to_string())),
        }
    }
}
