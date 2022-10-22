use std::collections::HashMap;

use futures::TryFutureExt;
use crate::{Jwk, KeysResponse};

pub async fn get_jwks(
    jwks_url: &str,
) -> Result<HashMap<String, Jwk>, reqwest::Error> {
    reqwest::get(jwks_url)
        .and_then(|resp| resp.json::<KeysResponse>())
        .and_then(|keys_resp| {
            keys_resp.keys.iter().fold(
                HashMap::<String, Jwk>::new(),
                move |mut key_map, key| {
                    key_map.insert(key.kid.clone(), key.clone());
                    key_map
                },
            )
        })
        .await
}
