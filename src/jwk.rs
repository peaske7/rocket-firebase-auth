use std::collections::HashMap;

use crate::{Jwk, KeysResponse};
use futures::TryFutureExt;

pub async fn jwks(
    jwks_url: &str,
) -> Result<HashMap<String, Jwk>, reqwest::Error> {
    reqwest::get(jwks_url)
        .and_then(|resp| resp.json::<KeysResponse>())
        .map_ok(|keys_resp| {
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
