//! JWKs fetcher module

use std::collections::HashMap;

use crate::errors::AuthError;
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};

/// Represents the Jwk contents that is returned from Google's JWKs endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Base64 URL encoded string, public exponent
    pub e:   String,
    /// The algorithm used. In Firebase's case, RS256
    pub alg: String,
    /// Key type. In Firebase's case, RSA
    pub kty: String,
    /// Key ID. Used to match to specific key in JWKs
    pub kid: String,
    /// Base64 URL encoded string, modulus
    pub n:   String,
}

impl Jwk {
    /// Creates a new Firebase Jwk with valid defaults
    pub fn new(kid: &str, n: &str) -> Self {
        Self {
            e:   "AQAB".to_string(),
            alg: "RS256".to_string(),
            kty: "RSA".to_string(),
            kid: kid.to_string(),
            n:   n.to_string(),
        }
    }
}

/// A vector representation of the JWKs list we receive as a response from Google
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysResponse {
    pub keys: Vec<Jwk>,
}

/// A struct representation of the Kid for the Jwk
#[derive(Eq, Hash, PartialEq, Debug)]
pub struct Kid(pub String);

/// Fetches a list of JWKs
pub(crate) async fn jwks(
    jwks_url: &str,
) -> Result<HashMap<Kid, Jwk>, AuthError> {
    reqwest::get(jwks_url)
        .and_then(|resp| resp.json::<KeysResponse>())
        .map_ok(|keys_resp| {
            keys_resp.keys.into_iter().fold(
                HashMap::<Kid, Jwk>::new(),
                |mut key_map, key| {
                    key_map.insert(Kid(key.kid.clone()), key);
                    key_map
                },
            )
        })
        .map_err(AuthError::from)
        .await
}
