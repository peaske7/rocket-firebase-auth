//! Token encoding/decoding module

#[cfg(feature = "encode")]
use chrono::Utc;
use futures::TryFutureExt;
#[cfg(feature = "encode")]
use jsonwebtoken::EncodingKey;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[cfg(feature = "encode")]
use crate::firebase_auth::AUD_URL;
use crate::{
    errors::{AuthError, InvalidJwt},
    firebase_auth::{FirebaseAuth, JWKS_URL},
    jwk::{jwks, Kid},
};

/// The claims of a decoded JWT token used in firebase
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt {
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub sub: String,
}

/// String representation of an encoded JWT token
#[cfg(feature = "encode")]
#[derive(Debug)]
pub struct EncodedToken(pub String);

/// A representation of a decoded JWT token
#[derive(Debug)]
pub struct DecodedToken {
    pub header: Header,
    pub claims: Jwt,
}

/// Create a validator used for decoding JWT tokens, provided by jsonwebtokens
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
    /// Creates a new Jwt struct.
    #[cfg(feature = "encode")]
    pub fn new(uid: &str) -> Self {
        let iat = Utc::now().timestamp() as u64;
        Self {
            aud: AUD_URL.to_string(),
            iat,
            exp: iat + (60 * 60),
            sub: uid.to_string(),
        }
    }

    /// Creates a new encoded token
    #[cfg(feature = "encode")]
    pub fn encode(
        uid: &str,
        firebase_auth: &FirebaseAuth,
    ) -> Result<EncodedToken, AuthError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(firebase_auth.credentials.private_key_id.to_string());

        EncodingKey::from_rsa_pem(
            firebase_auth.credentials.private_key.as_bytes(),
        )
        .and_then(|key| jsonwebtoken::encode(&header, &Jwt::new(uid), &key))
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
    ///     firebase_auth::FirebaseAuth,
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
        Self::verify_with_jwks_url(token, JWKS_URL, firebase_auth).await
    }

    /// Exposes the `jwks_url` field for testing purposes
    pub async fn verify_with_jwks_url(
        token: &str,
        jwks_url: &str,
        firebase_auth: &FirebaseAuth,
    ) -> Result<DecodedToken, AuthError> {
        let kid = decode_header(token).map_err(AuthError::from).and_then(
            |header| {
                header
                    .kid
                    .map(Kid)
                    .ok_or(AuthError::InvalidJwt(InvalidJwt::MissingKid))
            },
        )?;

        let jwk = jwks(jwks_url)
            .and_then(|mut key_map| async move {
                key_map
                    .remove(&kid)
                    .ok_or(AuthError::InvalidJwt(InvalidJwt::MissingJwk))
            })
            .await?;

        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .and_then(|key| {
                jsonwebtoken::decode::<Jwt>(
                    token,
                    &key,
                    &build_validation(&firebase_auth.credentials.project_id),
                )
            })
            .map(|token_data| DecodedToken {
                header: token_data.header,
                claims: token_data.claims,
            })
            .map_err(AuthError::from)
    }
}
