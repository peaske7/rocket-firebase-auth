//! Structs and functions essential and initializing Firebase Auth

#[cfg(feature = "env")]
use crate::errors::{AuthError, Env};

#[cfg(feature = "env")]
use dotenvy;
#[cfg(feature = "env")]
use serde_json;

use serde::Deserialize;
#[cfg(feature = "env")]
use std::{env, fs::read_to_string};

/// Endpoint to fetch JWKs when verifying firebase tokens
pub static JWKS_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

/// A partial representation of firebase admin object provided by firebase.
///
/// The fields in the firebase admin object is necessary when encoding and
/// decoding tokens. All fields should be kept secret.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub project_id:     String,
    pub private_key_id: String,
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
    /// use rocket_firebase_auth::firebase_auth::FirebaseAuth;
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
