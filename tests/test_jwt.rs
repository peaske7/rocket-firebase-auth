mod common;

use crate::common::utils::{
    load_scenario,
    mock_jwk_issuer,
    setup_mock_server,
    TEST_JWKS_URL,
};
use rocket_firebase_auth::{
    errors::{AuthError, InvalidJwt},
    firebase_auth::FirebaseAuth,
    jwt::Jwt,
};

#[tokio::test]
async fn missing_kid() {
    let token_without_kid = load_scenario("missing_kid").token;
    let firebase_auth = FirebaseAuth::default();
    let decoded_token =
        Jwt::verify(token_without_kid.as_str(), &firebase_auth).await;

    assert!(decoded_token.is_err());
    assert!(matches!(
        decoded_token.err().unwrap(),
        AuthError::InvalidJwt(InvalidJwt::MissingKid)
    ));
}

// Test for when the JWK issuer return empty list
#[tokio::test]
async fn missing_jwk() {
    let mock_server = setup_mock_server().await;
    let scenario = load_scenario("missing_jwk");

    // JWK issue returns empty list of jwks
    mock_jwk_issuer(Vec::new().as_slice())
        .expect(1)
        .mount(&mock_server)
        .await;

    let firebase_auth = FirebaseAuth::default().set_jwks_url(TEST_JWKS_URL);
    let decoded_token =
        Jwt::verify(scenario.token.as_str(), &firebase_auth).await;

    assert!(decoded_token.is_err());
    assert!(matches!(
        decoded_token.err().unwrap(),
        AuthError::InvalidJwt(InvalidJwt::MatchingJwkNotFound)
    ))
}
