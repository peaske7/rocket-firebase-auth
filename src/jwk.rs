//! JWKs fetcher module

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{errors::Error, FirebaseAuth};

/// Represents the Jwk contents that is returned from Google's JWKs endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Base64 URL encoded string, public exponent
    pub e: String,
    /// The algorithm used. In Firebase's case, RS256
    pub alg: String,
    /// Key type. In Firebase's case, RSA
    pub kty: String,
    /// Key ID. Used to match to specific key in JWKs
    pub kid: String,
    /// Base64 URL encoded string, modulus
    pub n: String,
}

impl Jwk {
    const EXPONENT: &str = "AQAB";
    const ALGORITHM: &str = "RS256";
    const KEY_TYPE: &str = "RSA";

    /// Creates a new Firebase Jwk with valid defaults
    pub fn new(kid: &str, n: &str) -> Self {
        Self {
            e: Self::EXPONENT.to_string(),
            alg: Self::ALGORITHM.to_string(),
            kty: Self::KEY_TYPE.to_string(),
            kid: kid.to_string(),
            n: n.to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

impl FirebaseAuth {
    /// Fetches a list of JWKs
    ///
    /// The jwks_url endpoint (google identity kit by default) is called and is
    /// expected to return a list of JWKs. The list is converted into a lookup table
    /// for the Jwk by Kid.
    pub(crate) async fn jwks(&self) -> Result<HashMap<String, Jwk>, Error> {
        let response = self.client.get(&self.jwks_url).send().await?;
        let jwks: JwksResponse = response.json().await?;
        let table = jwks.keys.into_iter().fold(
            HashMap::<String, Jwk>::new(),
            |mut key_map, jwk| {
                key_map.insert(jwk.kid.clone(), jwk);
                key_map
            },
        );

        Ok(table)
    }
}
