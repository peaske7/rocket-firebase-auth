use chrono::Utc;
use jsonwebtoken::{
    decode_header,
    errors::ErrorKind,
    Algorithm,
    DecodingKey,
    EncodingKey,
    Header,
    Validation,
};

use crate::{errors::AuthError, jwk::jwks, FirebaseAdmin, Jwt};

fn build_validation(project_id: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[format!(
        "https://securetoken.google.com/{}",
        project_id
    )]);
    validation.set_audience(&[project_id]);
    validation
}

impl Jwt {
    pub fn new(audience: &str, uid: String) -> Self {
        let iat = Utc::now().timestamp() as u64;
        Jwt {
            aud: audience.to_string(),
            iat,
            exp: iat + (60 * 60),
            sub: uid,
        }
    }

    pub fn encode(
        audience: &str,
        private_key_id: String,
        private_key: String,
        uid: String,
    ) -> Result<String, AuthError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(private_key_id);

        EncodingKey::from_rsa_pem(str::as_bytes(&private_key))
            .and_then(|key| {
                jsonwebtoken::encode(&header, &Self::new(audience, uid), &key)
            })
            .map_err(AuthError::from)
    }

    pub async fn verify(
        token: &str,
        firebase_config: &FirebaseAdmin,
        jwks_url: &str,
    ) -> Result<jsonwebtoken::TokenData<Jwt>, AuthError> {
        let kid = decode_header(token).map_err(AuthError::from).and_then(
            |header| {
                header.kid.ok_or_else(|| {
                    AuthError::InvalidJwt(format!(
                        "{:?}",
                        ErrorKind::InvalidToken
                    ))
                })
            },
        )?;

        let jwk = jwks(jwks_url).await.map_err(AuthError::from).and_then(
            |mut key_map| {
                key_map.remove(&kid).ok_or_else(|| {
                    AuthError::InvalidJwt("Missing Jwk".to_string())
                })
            },
        )?;

        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .and_then(|key| {
                jsonwebtoken::decode::<Jwt>(
                    token,
                    &key,
                    &build_validation(&firebase_config.project_id),
                )
            })
            .map_err(AuthError::from)
    }
}
