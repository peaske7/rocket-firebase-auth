mod common;

use crate::common::utils::{
    load_scenario,
    mock_jwk_issuer,
    setup_mock_server,
    TEST_JWKS_URL,
};
use rocket_firebase_auth::{firebase_auth::FirebaseAuth, jwk::Jwk, jwt::Jwt};

#[tokio::test]
async fn should_succeed_with_env() {
    let mock_server = setup_mock_server().await;
    let scenario = load_scenario("success");
    let jwk = Jwk::new(scenario.kid.as_str(), scenario.jwk_n.as_str());

    mock_jwk_issuer(vec![jwk].as_slice())
        .expect(1)
        .mount(&mock_server)
        .await;

    let firebase_auth = FirebaseAuth::try_from_env("FIREBASE_CREDS")
        .unwrap()
        .set_jwks_url(TEST_JWKS_URL);

    let decoded_token =
        Jwt::verify(scenario.token.as_str(), &firebase_auth).await;

    assert!(decoded_token.is_ok());

    let decoded_token = decoded_token.unwrap();

    assert_eq!(decoded_token.uid, "some-uid");
    assert!(decoded_token.expires_at > decoded_token.issued_at);
}

#[tokio::test]
async fn should_succeed_with_env_with_filename() {
    let mock_server = setup_mock_server().await;
    let scenario = load_scenario("success");
    let jwk = Jwk::new(scenario.kid.as_str(), scenario.jwk_n.as_str());

    mock_jwk_issuer(vec![jwk].as_slice())
        .expect(1)
        .mount(&mock_server)
        .await;

    let firebase_auth = FirebaseAuth::try_from_env_with_filename(
        "./tests/env_files/.env.test",
        "FIREBASE_CREDS",
    )
    .unwrap()
    .set_jwks_url(TEST_JWKS_URL);
    let decoded_token =
        Jwt::verify(scenario.token.as_str(), &firebase_auth).await;

    assert!(decoded_token.is_ok());

    let decoded_token = decoded_token.unwrap();

    assert_eq!(decoded_token.uid, "some-uid");
    assert!(decoded_token.expires_at > decoded_token.issued_at);
}

#[tokio::test]
async fn should_succeed_with_json_file() {
    let mock_server = setup_mock_server().await;
    let scenario = load_scenario("success");
    let jwk = Jwk::new(scenario.kid.as_str(), scenario.jwk_n.as_str());

    mock_jwk_issuer(vec![jwk].as_slice())
        .expect(1)
        .mount(&mock_server)
        .await;

    let firebase_auth =
        FirebaseAuth::try_from_json_file("tests/env_files/firebase-creds.json")
            .unwrap()
            .set_jwks_url(TEST_JWKS_URL);
    let decoded_token =
        Jwt::verify(scenario.token.as_str(), &firebase_auth).await;

    assert!(decoded_token.is_ok());

    let decoded_token = decoded_token.unwrap();

    assert_eq!(decoded_token.uid, "some-uid");
    assert!(decoded_token.expires_at > decoded_token.issued_at);
}
