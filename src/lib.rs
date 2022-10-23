mod bearer_token;
mod errors;
mod jwk;
mod jwt;

use serde::{Deserialize, Serialize};

pub static FIREBASE_AUTHENTICATION_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

#[derive(Clone, Debug, Deserialize)]
pub struct FirebaseAuth {
    pub firebase_admin: FirebaseAdmin,
    pub jwks_url:       String,
}

impl FirebaseAuth {
    pub fn new(firebase_admin: FirebaseAdmin, jwks_url: String) -> Self {
        FirebaseAuth {
            firebase_admin,
            jwks_url,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct FirebaseAdmin {
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

#[derive(Debug)]
pub struct BearerToken(pub String);
