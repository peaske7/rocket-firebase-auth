mod bearer_token;
mod errors;
mod jwk;
mod jwt;

use rocket::{
    http::Status,
    outcome::Outcome,
    request,
    request::FromRequest,
    Request,
};
use serde::{Deserialize, Serialize};

pub static FIREBASE_AUTHENTICATION_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

#[derive(Clone, Debug, Deserialize)]
pub struct FirebaseAuth {
    firebase_config: FirebaseConfig,
    jwks_url:        String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FirebaseConfig {
    pub project_id:     String,
    pub private_key_id: String,
    pub private_key:    String,
    pub client_email:   String,
    pub client_id:      String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt {
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub sub: String,
}

pub fn create_custom_token(uid: &str) -> Result<String, AuthError> {
    let firebase_config = FirebaseConfig::new();

    Jwt::encode(
        FIREBASE_AUTHENTICATION_AUDIENCE,
        firebase_config.private_key_id,
        firebase_config.private_key,
        uid.to_string(),
    )
}

#[derive(Debug)]
pub struct BearerToken(pub String);
