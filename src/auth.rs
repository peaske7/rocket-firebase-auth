//! Structs and functions essential and initializing Firebase Auth

use crate::errors::{AuthError, Env, InvalidJwt};

#[cfg(feature = "env")]
use dotenvy;
#[cfg(feature = "env")]
use serde_json;

use crate::{
    bearer_token::BearerToken,
    jwk::{jwks, Kid},
};
#[cfg(feature = "encode")]
use chrono::Utc;
use futures::TryFutureExt;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Validation};
#[cfg(feature = "encode")]
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
#[cfg(feature = "env")]
use std::{env, fs::read_to_string};

/// Endpoint to fetch JWKs when verifying firebase tokens
pub static JWKS_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

/// The claims of a decoded JWT token used in firebase
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt {
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub sub: String,
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

/// A partial representation of firebase admin object provided by firebase.
///
/// The fields in the firebase admin object is necessary when encoding and
/// decoding tokens. All fields should be kept secret.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    /// The project_id will be used as the `aud` in JWT tokens
    pub project_id:     String,
    /// The private_key_id will be used as the `kid` in JWT tokens
    pub private_key_id: String,
    /// The private_key is the private RSA key used to sign the token
    pub private_key:    String,
    pub client_email:   String,
    pub client_id:      String,
}

/// Firebase Auth instance
///
/// The `jwks_url` field is used to specify the endpoint to fetch JWKs from.
/// In production, this should always be set to the static `JWKS_URL` value.
/// However, in testing or staging environments when you want finer grained control
/// over the values used, specify as, for example, localhost to mock the response.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct FirebaseAuth {
    pub(crate) credentials: Credentials,
    pub(crate) jwks_url:    String,
}

impl Default for FirebaseAuth {
    fn default() -> Self {
        Self {
            credentials: Credentials {
                project_id:     String::default(),
                private_key_id: String::default(),
                private_key:    String::default(),
                client_email:   String::default(),
                client_id:      String::default(),
            },
            jwks_url:    JWKS_URL.to_string(),
        }
    }
}

#[cfg(feature = "env")]
impl TryFrom<String> for FirebaseAuth {
    type Error = AuthError;

    fn try_from(credentials: String) -> Result<Self, Self::Error> {
        serde_json::from_str::<Credentials>(credentials.as_str())
            .map(|deserialized_credentials| {
                FirebaseAuth::new(deserialized_credentials)
            })
            .map_err(|e| {
                AuthError::Env(Env::InvalidFirebaseCredentials(e.to_string()))
            })
    }
}

impl FirebaseAuth {
    /// Create a new FirebaseAuth struct by providing Credentials
    pub fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            jwks_url: JWKS_URL.to_string(),
        }
    }

    /// Create a new FirebaseAuth struct from a dotenv file
    #[cfg(feature = "env")]
    pub fn try_from_env(variable_name: &str) -> Result<Self, AuthError> {
        Self::try_from_env_with_filename(".env", variable_name)
    }

    /// Create a new FirebaseAuth struct by providing a dotenv filepath
    ///
    /// This function is will most likely find its way in the codebase when
    /// supplying the `FirebaseAuth` dummy values in tests.
    #[cfg(feature = "env")]
    pub fn try_from_env_with_filename(
        filepath: &str,
        variable_name: &str,
    ) -> Result<Self, AuthError> {
        match dotenvy::from_filename(filepath) {
            Ok(_) => env::var(variable_name)
                .map_err(|e| {
                    AuthError::Env(Env::InvalidFirebaseCredentials(
                        e.to_string(),
                    ))
                })
                .and_then(|credentials| credentials.try_into()),
            Err(e) => Err(AuthError::Env(Env::MissingEnvFile(e.to_string()))),
        }
    }

    /// Create a new FirebaseAuth struct from a file with the credentials given
    /// by Firebase, but not in a `.env` file.
    #[cfg(feature = "env")]
    pub fn try_from_json_file(filepath: &str) -> Result<Self, AuthError> {
        // given file must be a `.json` file
        if !filepath.ends_with(".json") {
            Err(AuthError::Env(Env::InvalidFileFormat(format!(
                "Expected .json file. Received {filepath}"
            ))))
        } else {
            read_to_string(filepath)
                .map_err(|e| {
                    AuthError::Env(Env::InvalidFirebaseCredentials(
                        e.to_string(),
                    ))
                })
                .and_then(|credentials| credentials.try_into())
        }
    }

    /// Override jwks_url from default JWKS_URL value to a user defined one.
    ///
    /// In cases when you want to setup mocks for the JWKS (for example, when
    /// you want to always return the same JWKs), use `set_jwks_url` to override
    /// the default JWKS_URL value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_firebase_auth::auth::FirebaseAuth;
    ///
    /// async fn setup_auth() -> FirebaseAuth {
    ///   FirebaseAuth::try_from_env("FIREBASE_CREDS")
    ///     .unwrap()
    ///     .set_jwks_url("http://localhost:8080/jwks_url")
    /// }
    /// ```
    pub fn set_jwks_url(&self, url: &str) -> Self {
        Self {
            credentials: self.credentials.clone(),
            jwks_url:    url.to_string(),
        }
    }

    /// Creates a new encoded token
    ///
    /// Encode a JWT token with RS256 and an RSA private key provided by Firebase
    /// with the `uid` and `project_id` fields included as the claims.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rocket_firebase_auth::{
    ///     auth::FirebaseAuth,
    ///     errors::AuthError
    /// };
    ///
    /// async fn something(auth: &FirebaseAuth) {
    ///     let uid = "...";
    ///     let project_id = "...";
    ///     let encoded_token = auth.encode(uid).await?;
    /// }
    /// ```
    #[cfg(feature = "encode")]
    pub fn encode(&self, uid: &str) -> Result<EncodedToken, AuthError> {
        let header = Header {
            kid: Some(self.credentials.private_key_id.clone()),
            ..Header::new(Algorithm::RS256)
        };

        EncodingKey::from_rsa_pem(self.credentials.private_key.as_bytes())
            .and_then(|key| {
                jsonwebtoken::encode(
                    &header,
                    &Jwt::new(uid, &self.credentials.project_id),
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
    /// use futures::TryFutureExt;
    /// use rocket::{get, State, response::status, http::Status};
    /// use rocket_firebase_auth::{
    ///     bearer_token::BearerToken,
    ///     errors::AuthError,
    ///     auth::FirebaseAuth
    /// };
    ///
    /// struct ServerState {
    ///     pub auth: FirebaseAuth
    /// }
    ///
    /// #[get("/")]
    /// async fn authenticated_route(
    ///     state: &State<ServerState>,
    ///     token: BearerToken
    /// ) -> Status
    /// {
    ///     match state.auth.verify(&token).await {
    ///         Ok(decoded_token) => {
    ///             println!("Valid token. uid: {}", decoded_token.uid);
    ///             Status::Ok
    ///         }
    ///         Err(_) => {
    ///             println!("Invalid token.");
    ///             Status::Forbidden
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn verify(
        &self,
        token: &BearerToken,
    ) -> Result<DecodedToken, AuthError> {
        self.verify_from_string(token.as_str()).await
    }

    /// Verify Firebase Jwt token in string representation
    pub async fn verify_from_string(
        &self,
        token: &str,
    ) -> Result<DecodedToken, AuthError> {
        let kid = decode_header(token).map_err(AuthError::from).and_then(
            |header| {
                header
                    .kid
                    .map(Kid::from)
                    .ok_or(AuthError::InvalidJwt(InvalidJwt::MissingKid))
            },
        )?;

        let jwk = jwks(&self.jwks_url)
            .and_then(|mut key_map| async move {
                key_map.remove(&kid).ok_or(AuthError::InvalidJwt(
                    InvalidJwt::MatchingJwkNotFound,
                ))
            })
            .await?;

        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .and_then(|key| {
                jsonwebtoken::decode::<Jwt>(
                    token,
                    &key,
                    &build_validation(&self.credentials.project_id.clone()),
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

/// Create a validator used for decoding JWT tokens, provided by jsonwebtokens
fn build_validation(project_id: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation
        .set_issuer(&[format!("https://securetoken.google.com/{project_id}",)]);
    validation.set_audience(&[project_id]);
    validation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_fail_with_invalid_env_var() {
        let firebase_auth = FirebaseAuth::try_from_env("INVALID_VAR_NAME");

        let _desired_error = AuthError::Env(Env::InvalidFirebaseCredentials(
            "environment variable not found".to_string(),
        ));
        assert!(firebase_auth.is_err());
        assert!(matches!(firebase_auth.err().unwrap(), _desired_error))
    }

    #[test]
    fn should_fail_with_invalid_json_contents() {
        let firebase_auth = FirebaseAuth::try_from_json_file(
            "tests/env_files/firebase-creds.empty.json",
        );

        let res = matches!(
            firebase_auth.err().unwrap(),
            AuthError::Env(Env::InvalidFirebaseCredentials(_))
        );

        assert!(res);
    }

    #[test]
    fn should_succeed_with_set_jwks_url() {
        let firebase_auth = FirebaseAuth::try_from_json_file(
            "tests/env_files/firebase-creds.json",
        )
        .map(|creds| creds.set_jwks_url("some_dummy_value"))
        .unwrap();

        assert_eq!(firebase_auth.jwks_url, "some_dummy_value");
    }
}
