mod common;

use crate::common::{
    load_scenario,
    mock_jwk_issuer,
    setup_mock_server,
    TEST_JWKS_URL,
};
use rocket_firebase_auth::{
    errors::{Error, InvalidJwt},
    FirebaseAuth,
};

#[tokio::test]
async fn missing_kid() {
    let token_without_kid = load_scenario("missing_kid").token;
    let decoded_token = FirebaseAuth::default()
        .verify(token_without_kid.as_str())
        .await;

    assert!(decoded_token.is_err());
    assert!(matches!(
        decoded_token.err().unwrap(),
        Error::InvalidJwt(InvalidJwt::MissingKid)
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

    let decoded_token = FirebaseAuth::builder()
        .jwks_url(TEST_JWKS_URL)
        .build()
        .unwrap()
        .verify(scenario.token.as_str())
        .await;

    assert!(decoded_token.is_err());
    assert!(matches!(
        decoded_token.err().unwrap(),
        Error::InvalidJwt(InvalidJwt::MatchingJwkNotFound)
    ))
}
