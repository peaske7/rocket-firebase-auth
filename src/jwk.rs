use std::collections::HashMap;

use crate::errors::AuthError;
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub e:   String,
    pub alg: String,
    pub kty: String,
    pub kid: String,
    pub n:   String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysResponse {
    pub keys: Vec<Jwk>,
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub struct Kid(pub String);

pub async fn jwks(jwks_url: &str) -> Result<HashMap<Kid, Jwk>, AuthError> {
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
