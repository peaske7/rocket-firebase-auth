//! JWKs fetcher module

use std::collections::HashMap;

use crate::{auth::FirebaseAuth, errors::AuthError};
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

impl FirebaseAuth {
    /// Fetches a list of JWKs
    ///
    /// The jwks_url endpoint (google identity kit by default) is called and is
    /// expected to return a list of JWKs. The list is converted into a lookup table
    /// for the Jwk by Kid.
    pub(crate) async fn jwks(&self) -> Result<HashMap<String, Jwk>, AuthError> {
        self.client
            .get(&self.jwks_url)
            .send()
            .and_then(|resp| resp.json::<Vec<Jwk>>())
            .map_ok(|keys_resp| {
                keys_resp.into_iter().fold(
                    HashMap::<String, Jwk>::new(),
                    |mut key_map, jwk| {
                        key_map.insert(jwk.kid.clone(), jwk);
                        key_map
                    },
                )
            })
            .map_err(AuthError::from)
            .await
    }
}
