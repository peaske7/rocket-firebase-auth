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
#[derive(Debug, PartialEq, Eq)]
pub struct BearerToken(String);

impl BearerToken {
    pub fn new(bearer_token: String) -> Self {
        Self(bearer_token)
    }

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

#[cfg(test)]
mod test {
    use super::*;
    use test_case::test_case;

    #[test_case("bearer token", true; "happy path")]
    #[test_case("bearer bearer ", true; "bearers with spaces")]
    #[test_case("bearer", false; "just bearer")]
    #[test_case("bearer ", false; "bearer with a space")]
    #[test_case("bearer   ", false; "bearer with many spaces")]
    #[test_case("", false; "empty string")]
    #[test_case(" bearer", false; "leading spaces should not count as single token")]
    #[test_case(" token bearer", false; "bearer should come first")]
    fn test_try_from(header: &str, should_succeed: bool) {
        assert_eq!(BearerToken::try_from(header).is_ok(), should_succeed);
    }
}
