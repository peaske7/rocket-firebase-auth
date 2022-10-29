//! Token encoding/decoding module

#[cfg(feature = "encode")]
use chrono::Utc;
use futures::TryFutureExt;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Validation};
#[cfg(feature = "encode")]
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};

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

/// The decoded Firebase JWT token with fields renamed to match Firebase's
/// mapped values.
///
/// ```txt
/// jwt.claims.iat => decoded_token.issued_at
/// jwt.claims.exp => decoded_token.expires_at
/// jwt.claims.sub => decoded_token.uid
/// ```
#[derive(Debug)]
pub struct DecodedToken {
    /// Time the token was issued at in UNIX epoch. Must be in the past
    pub issued_at:  u64,
    /// Time the token is set to expire in UNIX epoch. Must be in the future.
    pub expires_at: u64,
    /// User ID issued by Firebase
    pub uid:        String,
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
    /// Creates a new Jwt token
    ///
    /// The new token is created with a given Firebase `uid` and `project_id`.
    #[cfg(feature = "encode")]
    pub fn new(uid: &str, project_id: &str) -> Self {
        let iat = Utc::now().timestamp() as u64;
        Self {
            aud: project_id.to_string(),
            iat,
            exp: iat + (60 * 60),
            sub: uid.to_string(),
        }
    }

    /// Creates a new encoded token
    ///
    /// Encode a JWT token with RS256 and an RSA private key provided by Firebase
    /// with the `uid` and `project_id` fields included as the claims.
    ///
    /// # Examples
    ///
    /// ```rust, ignore
    /// use rocket_firebase_auth::{
    ///     jwt::{Jwt, EncodedToken},
    ///     firebase_auth::FirebaseAuth,
    ///     errors::AuthError
    /// };
    ///
    /// async fn something() {
    ///     ...
    ///     let uid = "...";
    ///     let project_id = "...":
    ///     let encoded_token = Jwt::encode(uid, project_id).await?;
    /// }
    /// ```
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
        .and_then(|key| {
            jsonwebtoken::encode(
                &header,
                &Jwt::new(uid, &firebase_auth.credentials.project_id),
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
    ///     jwt::{Jwt, DecodedToken},
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
                issued_at:  token_data.claims.iat,
                expires_at: token_data.claims.exp,
                uid:        token_data.claims.sub,
            })
            .map_err(AuthError::from)
    }
}
