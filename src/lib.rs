//! # rocket-firebase-auth
//!
//! The `rocket-firebase-auth` crate provides an easy, batteries included
//! firebase authentication library for `Rocket`. The library is built for
//! servers that use Firebase tokens as a means of authentication from the
//! client.
//!
//! ## Example
//!
//! ```rust, no_run
//! use rocket::{get, http::Status, routes, Build, Rocket, State};
//! use rocket_firebase_auth::{BearerToken, FirebaseAuth};
//!
//! struct ServerState {
//!     auth: FirebaseAuth,
//! }
//!
//! // Example function that returns an `Ok` and prints the verified user's uid.
//! // If the token is invalid, return with a `Forbidden` status code.
//! #[get("/")]
//! async fn hello_world(state: &State<ServerState>, token: BearerToken) -> Status {
//!     let token = state.auth.verify(&token).await; // verify token
//!
//!     match token // extract uid from decoded token
//!     {
//!         Ok(token) => {
//!             println!("Authentication succeeded with uid={}", token.uid);
//!             Status::Ok
//!         }
//!         Err(_) => {
//!             println!("Authentication failed.");
//!             Status::Forbidden
//!         }
//!     }
//! }
//!
//! #[rocket::launch]
//! async fn rocket() -> Rocket<Build> {
//!     let firebase_auth = FirebaseAuth::builder()
//!         .json_file("firebase-credentials.json")
//!         .build()
//!         .unwrap();
//!
//!     rocket::build()
//!         .mount("/", routes![hello_world])
//!         .manage(ServerState {
//!             auth: firebase_auth,
//!         })
//! }
//! ```
//!
//! ## Optional Features
//!
//! By default `env` and `rocket` as included as features.
//! The following are a list of [Cargo features][cargo-features] that can be
//! enabled or disabled:
//!
//! - **`env`**: Includes functions that helps in initializing Firebase Auth
//!   from dotenv files
//! - **`encode`**: Adds support for encoding tokens
//! - **`rocket`**: Implements the FromRequest trait for `BearerToken`, so that
//!   rocket endpoints can easily access the token as an input parameter.
//!
#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]
mod bearer_token;
pub use bearer_token::BearerToken;
mod firebase_token;
pub use firebase_token::FirebaseToken;
pub mod errors;
pub mod jwk;
pub mod plugins;

use crate::errors::{Error, InvalidJwt};

#[cfg(feature = "env")]
pub use dotenvy;
#[cfg(feature = "env")]
pub use serde_json;

#[cfg(feature = "encode")]
use chrono::Utc;
pub use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Validation};
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
/// jwt.claims.iat => decoded_token.issued_at
/// jwt.claims.exp => decoded_token.expires_at
/// jwt.claims.sub => decoded_token.uid
#[derive(Debug)]
pub struct DecodedToken {
    /// Time the token was issued at in UNIX epoch. Must be in the past
    pub issued_at: u64,
    /// Time the token is set to expire in UNIX epoch. Must be in the future.
    pub expires_at: u64,
    /// User ID issued by Firebase
    pub uid: String,
}

/// A partial representation of firebase admin object provided by firebase.
///
/// The fields in the firebase admin object is necessary when encoding and
/// decoding tokens. All fields should be kept secret.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Credentials {
    /// The project_id will be used as the `aud` in JWT tokens
    pub project_id: String,
    /// The private_key_id will be used as the `kid` in JWT tokens
    pub private_key_id: String,
    /// The private_key is the private RSA key used to sign the token
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
}

/// Firebase Auth instance
///
/// The `jwks_url` field is used to specify the endpoint to fetch JWKs from.
/// In production, this should always be set to the static `JWKS_URL` value.
/// However, in testing or staging environments when you want finer grained control
/// over the values used, specify as, for example, localhost to mock the response.
#[derive(Debug, Clone)]
pub struct FirebaseAuth {
    pub(crate) credentials: Credentials,
    pub jwks_url: String,
    pub(crate) client: reqwest::Client,
}

impl Default for FirebaseAuth {
    fn default() -> Self {
        let client = reqwest::Client::new();
        Self {
            credentials: Credentials::default(),
            jwks_url: JWKS_URL.to_string(),
            client,
        }
    }
}

#[derive(Debug, Clone)]
pub enum EnvSource {
    Var,
    #[cfg(feature = "env")]
    Env {
        file_path: String,
        variable: String,
    },
    #[cfg(feature = "env")]
    Json(String),
}

#[derive(Debug, Clone)]
pub struct FirebaseAuthBuilder {
    credentials: Credentials,
    jwks_url: String,
    env_source: EnvSource,
}

impl Default for FirebaseAuthBuilder {
    fn default() -> Self {
        Self {
            credentials: Credentials::default(),
            jwks_url: JWKS_URL.to_string(),
            #[cfg(feature = "env")]
            env_source: EnvSource::Var,
        }
    }
}

impl FirebaseAuthBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add credentials to the builder
    ///
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_firebase_auth::{Credentials, FirebaseAuth};
    ///
    /// let credentials = Credentials {
    ///     project_id: "my-project".to_string(),
    ///     private_key_id: "my-private-key-id".to_string(),
    ///     private_key: "my-private-key".to_string(),
    ///     client_email: "my-client-email".to_string(),
    ///     client_id: "my-client-id".to_string(),
    /// };
    ///
    /// let auth = FirebaseAuth::builder()
    ///     .credentials(credentials)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Add a custom jwks_url to the builder
    ///
    /// This is useful when you want to mock the jwks endpoint in tests or
    /// when you want to use a custom jwks endpoint in staging or development
    /// environments.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_firebase_auth::FirebaseAuth;
    ///
    /// let auth = FirebaseAuth::builder()
    ///     .jwks_url("https://my-custom-jwks-url.com")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn jwks_url(mut self, jwks_url: &str) -> Self {
        self.jwks_url = jwks_url.to_string();
        self
    }

    /// Set credentials by reading from `.env` file
    ///
    /// If you want to specify a custom `.env` file, use the `env_file` function.
    /// This function will specifically read from the `.env` file.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// use rocket_firebase_auth::FirebaseAuth;
    ///
    /// let auth = FirebaseAuth::builder()
    ///     .env("FIREBASE_CREDENTIALS")
    ///     .build()
    ///     .unwrap();
    /// ```
    #[cfg(feature = "env")]
    pub fn env(mut self, variable_name: &str) -> Self {
        self.env_source = EnvSource::Env {
            file_path: ".env".to_string(),
            variable: variable_name.to_string(),
        };
        self
    }

    /// Set credentials by providing a dotenv filepath
    ///
    /// This function is will most likely find its way in the codebase when
    /// supplying the `FirebaseAuth` dummy values in tests, or if the user
    /// stringified the json credentials and stored it in a `.env` file.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// use rocket_firebase_auth::FirebaseAuth;
    ///
    /// let auth = FirebaseAuth::builder()
    ///     .env_file(".env", "FIREBASE_CREDENTIALS")
    ///     .build()
    ///     .unwrap();
    /// ```
    #[cfg(feature = "env")]
    pub fn env_file(mut self, filepath: &str, variable_name: &str) -> Self {
        self.env_source = EnvSource::Env {
            file_path: filepath.to_string(),
            variable: variable_name.to_string(),
        };
        self
    }

    /// Set credentials by providing a json filepath
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// use rocket_firebase_auth::FirebaseAuth;
    ///
    /// let auth = FirebaseAuth::builder()
    ///     .json_file("credentials.json")
    ///     .build()
    ///     .unwrap();
    /// ```
    #[cfg(feature = "env")]
    pub fn json_file(mut self, filepath: &str) -> Self {
        self.env_source = EnvSource::Json(filepath.to_string());
        self
    }

    /// Build the `FirebaseAuth` instance
    ///
    /// Tries to build the `FirebaseAuth` instance from the provided config
    /// values. If the `env_file` or `json_file` functions were used, this
    /// function will try to read the file and parse the credentials from it.
    /// Credentials will be set by the function last used to set them (for
    /// example, if you call `env_file` and then `credentials`, the credentials
    /// set by `credentials` function will be used).
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// use rocket_firebase_auth::FirebaseAuth;
    ///
    /// let auth = FirebaseAuth::builder()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn build(self) -> Result<FirebaseAuth, Error> {
        let credentials = match self.env_source {
            #[cfg(feature = "env")]
            EnvSource::Env {
                file_path,
                variable,
            } => {
                dotenvy::from_filename(file_path)?;
                env::var(variable).map_err(Error::from).and_then(
                    |credentials| {
                        serde_json::from_str::<Credentials>(&credentials)
                            .map_err(Error::from)
                    },
                )
            }
            #[cfg(feature = "env")]
            EnvSource::Json(filepath) => read_to_string(filepath)
                .map_err(Error::from)
                .and_then(|credentials| {
                    serde_json::from_str::<Credentials>(&credentials)
                        .map_err(Error::from)
                }),
            _ => Ok(self.credentials),
        }?;

        Ok(FirebaseAuth {
            credentials,
            jwks_url: self.jwks_url,
            client: reqwest::Client::new(),
        })
    }
}

impl FirebaseAuth {
    /// Create a new FirebaseAuth struct by providing Credentials
    pub fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            jwks_url: JWKS_URL.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a new FirebaseAuth builder
    pub fn builder() -> FirebaseAuthBuilder {
        FirebaseAuthBuilder::new()
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
    pub fn encode(&self, uid: &str) -> Result<EncodedToken, Error> {
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
            .map_err(Error::from)
    }

    /// Verifies given JWT token
    ///
    /// Extract a kid from a given token if exists. Look for a jwk that is
    /// mapped to the extracted kid from a map of kid-jwk pairs. Return a
    /// decoded token using the jwk and a firebase project_id.
    ///
    /// # Examples
    ///
    /// ```rust, no_run
    /// use rocket::{get, State, response::status, http::Status};
    /// use rocket_firebase_auth::{
    ///     BearerToken,
    ///     FirebaseAuth
    /// };
    ///
    /// struct ServerState {
    ///     auth: FirebaseAuth
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
    ) -> Result<DecodedToken, Error> {
        self.verify_token(token.as_str()).await
    }

    /// Verify Firebase Jwt token in string representation
    pub async fn verify_token(
        &self,
        token: &str,
    ) -> Result<DecodedToken, Error> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[format!(
            "https://securetoken.google.com/{}",
            &self.credentials.project_id
        )]);
        validation.set_audience(&[&self.credentials.project_id]);

        let kid =
            decode_header(token)
                .map_err(Error::from)
                .and_then(|header| {
                    header.kid.ok_or(Error::InvalidJwt(InvalidJwt::MissingKid))
                })?;

        let jwk = self.jwks().await.and_then(|mut key_map| {
            key_map
                .remove(&kid)
                .ok_or(Error::InvalidJwt(InvalidJwt::MatchingJwkNotFound))
        })?;

        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .and_then(|key| {
                jsonwebtoken::decode::<Jwt>(token, &key, &validation)
            })
            .map(|token_data| DecodedToken {
                issued_at: token_data.claims.iat,
                expires_at: token_data.claims.exp,
                uid: token_data.claims.sub,
            })
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_fail_with_invalid_env_var() {
        let firebase_auth = FirebaseAuth::builder()
            .env_file(".env", "INVALID_VAR_NAME")
            .build();

        assert!(firebase_auth.is_err());
    }

    #[test]
    fn should_fail_with_invalid_json_contents() {
        let firebase_auth = FirebaseAuth::builder()
            .json_file("tests/env_files/firebase-creds.empty.json")
            .build();

        assert!(firebase_auth.is_err());
    }

    #[test]
    fn should_succeed_with_set_jwks_url() {
        let firebase_auth = FirebaseAuth::builder()
            .json_file("tests/env_files/firebase-creds.json")
            .jwks_url("some_dummy_value")
            .build();

        assert!(firebase_auth.is_ok());
        assert_eq!(firebase_auth.unwrap().jwks_url, "some_dummy_value");
    }
}
