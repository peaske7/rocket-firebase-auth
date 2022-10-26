use serde::Deserialize;

/// Endpoint to fetch JWKs when verifying firebase tokens
pub static JWKS_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
/// Firebase tokens' audience field
pub static FIREBASE_AUD_URL: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

#[derive(Debug, Deserialize)]
pub struct FirebaseAuth {
    pub firebase_admin: FirebaseAdmin,
    pub jwks_url:       String,
    pub aud_url:        String,
}

impl FirebaseAuth {
    /// Create a new FirebaseAuth instance by specifying every field
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

    /// Create a new FirebaseAuth instance with the default jwks and aud urls
    pub fn with_firebase_admin(firebase_admin: FirebaseAdmin) -> Self {
        FirebaseAuth {
            firebase_admin,
            jwks_url: JWKS_URL.to_string(),
            aud_url: FIREBASE_AUD_URL.to_string(),
        }
    }
}

/// A partial representation of firebase admin object provided by firebase.
///
/// The fields in the firebase admin object is necessary when encoding and
/// decoding tokens. All fields should be kept secret.
#[derive(Debug, Deserialize)]
pub struct FirebaseAdmin {
    pub project_id:     String,
    pub private_key_id: String,
    pub private_key:    String,
    pub client_email:   String,
    pub client_id:      String,
}
