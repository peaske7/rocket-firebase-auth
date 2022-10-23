pub mod bearer_token;
pub mod errors;
pub mod jwk;
pub mod jwt;

use serde::Deserialize;

pub static JWKS_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
pub static FIREBASE_AUD_URL: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

#[derive(Debug, Deserialize)]
pub struct FirebaseAuth {
    pub firebase_admin: FirebaseAdmin,
    pub jwks_url:       String,
    pub aud_url:        String,
}

impl FirebaseAuth {
    pub fn new(
        firebase_admin: FirebaseAdmin,
        jwks_url: &str,
        aud_url: &str,
    ) -> Self {
        FirebaseAuth {
            firebase_admin,
            jwks_url: jwks_url.to_string(),
            aud_url: aud_url.to_string(),
        }
    }

    pub fn with_firebase_admin(firebase_admin: FirebaseAdmin) -> Self {
        FirebaseAuth {
            firebase_admin,
            jwks_url: JWKS_URL.to_string(),
            aud_url: FIREBASE_AUD_URL.to_string(),
        }
    }
}

impl Default for FirebaseAuth {
    fn default() -> Self {
        Self {
            firebase_admin: FirebaseAdmin {
                project_id:     "".to_string(),
                private_key_id: "".to_string(),
                private_key:    "".to_string(),
                client_email:   "".to_string(),
                client_id:      "".to_string(),
            },
            jwks_url:       JWKS_URL.to_string(),
            aud_url:        FIREBASE_AUD_URL.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct FirebaseAdmin {
    pub project_id:     String,
    pub private_key_id: String,
    pub private_key:    String,
    pub client_email:   String,
    pub client_id:      String,
}
