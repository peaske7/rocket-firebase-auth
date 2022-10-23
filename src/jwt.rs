use chrono::Utc;
use futures::TryFutureExt;
use jsonwebtoken::{
    decode_header,
    errors::ErrorKind,
    Algorithm,
    DecodingKey,
    EncodingKey,
    Header,
    Validation,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::AuthError,
    jwk::{jwks, Kid},
    FirebaseAuth,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt {
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub sub: String,
}

#[derive(Debug)]
pub struct EncodedToken(pub String);

#[derive(Debug)]
pub struct DecodedToken {
    pub header: Header,
    pub claims: Jwt,
}

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
    pub fn new(uid: &str, audience: &str) -> Self {
        let iat = Utc::now().timestamp() as u64;
        Jwt {
            aud: audience.to_string(),
            iat,
            exp: iat + (60 * 60),
            sub: uid.to_string(),
        }
    }

    pub fn encode(
        uid: &str,
        firebase_auth: &FirebaseAuth,
    ) -> Result<EncodedToken, AuthError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid =
            Some(firebase_auth.firebase_admin.private_key_id.to_string());

        EncodingKey::from_rsa_pem(
            firebase_auth.firebase_admin.private_key.as_bytes(),
        )
        .and_then(|key| {
            jsonwebtoken::encode(
                &header,
                &Jwt::new(uid, &firebase_auth.aud_url),
                &key,
            )
        })
        .map(EncodedToken)
        .map_err(AuthError::from)
    }

    /// Verifies given JWT token
    ///
    /// Extract a kid from a given token if exists. Look for a jwk that is
    /// mapped to the extracted kid from a map of kid-jwk pairs. Return a
    /// decoded token using the jwk and a firebase project_id.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rocket_firebase_auth::{
    ///     jwt::{ Jwt, DecodedToken },
    ///     FirebaseAuth,
    ///     errors::AuthError
    /// };
    ///
    /// async fn decode_token(token: &str, firebase_auth: &FirebaseAuth)
    ///     -> Result<DecodedToken, AuthError>
    /// {
    ///     Jwt::verify("<some.encoded.token>", firebase_auth)
    ///         .await
    /// }
    /// ```
    pub async fn verify(
        token: &str,
        firebase_auth: &FirebaseAuth,
    ) -> Result<DecodedToken, AuthError> {
        let kid = decode_header(token).map_err(AuthError::from).and_then(
            |header| {
                header.kid.map(Kid).ok_or_else(|| {
                    AuthError::InvalidJwt(format!(
                        "{:?}",
                        ErrorKind::InvalidToken
                    ))
                })
            },
        )?;

        let jwk = jwks(&firebase_auth.jwks_url)
            .and_then(|mut key_map| async move {
                key_map.remove(&kid).ok_or_else(|| {
                    AuthError::InvalidJwt("Missing Jwk".to_string())
                })
            })
            .await?;

        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .and_then(|key| {
                jsonwebtoken::decode::<Jwt>(
                    token,
                    &key,
                    &build_validation(&firebase_auth.firebase_admin.project_id),
                )
            })
            .map(|token_data| DecodedToken {
                header: token_data.header,
                claims: token_data.claims,
            })
            .map_err(AuthError::from)
    }
}
