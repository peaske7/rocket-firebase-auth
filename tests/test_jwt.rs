use once_cell::sync::Lazy;
use rocket::serde::json::serde_json::json;
use rocket_firebase_auth::{
    errors::AuthError,
    jwk::{Jwk, KeysResponse},
    jwt::Jwt,
    FirebaseAdmin,
    FirebaseAuth,
};
use serde::Deserialize;
use std::{collections::HashMap, fs};
use wiremock::{
    matchers::{method, path},
    Mock,
    MockServer,
    ResponseTemplate,
};

#[derive(Debug, Deserialize)]
struct ScenarioFile {
    scenario: HashMap<String, Scenario>,
}

static SCENARIOS: Lazy<HashMap<String, Scenario>> = Lazy::new(|| {
    fs::read_to_string("./tests/scenarios.toml")
        .map(|contents| toml::from_str::<ScenarioFile>(&contents))
        .expect("Failed to parse scenarios from toml file.")
        .map(|file| {
            file.scenario.into_iter().fold(
                HashMap::new(),
                |mut accum, (key, scenario)| {
                    accum.insert(key, scenario);
                    accum
                },
            )
        })
        .expect("Failed to fold file contents into a hashmap")
});

#[derive(Debug, Clone, Deserialize)]
struct Scenario {
    pub desc:            Option<String>,
    pub token:           String,
    pub jwk_n:           String,
    pub kid:             String,
    pub rsa_public_key:  Option<String>,
    pub rsa_private_key: Option<String>,
}

fn firebase_auth() -> FirebaseAuth {
    FirebaseAuth::new(
        FirebaseAdmin {
            project_id:     "".to_string(),
            private_key_id: "".to_string(),
            private_key:    "".to_string(),
            client_email:   "".to_string(),
            client_id:      "".to_string(),
        },
        "http://localhost:8888/jwks_url",
        "http://localhost:8888/aud_url",
    )
}

async fn setup_mock_server() -> MockServer {
    let listener = std::net::TcpListener::bind("localhost:8888").unwrap();
    MockServer::builder().listener(listener).start().await
}

fn load_scenario(scenario_key: &str) -> Scenario {
    SCENARIOS.get(scenario_key).unwrap().clone()
}

impl From<Scenario> for Jwk {
    fn from(scenario: Scenario) -> Self {
        Self {
            e:   "AQAB".to_string(),
            alg: "RS256".to_string(),
            kty: "RSA".to_string(),
            kid: scenario.kid,
            n:   scenario.jwk_n,
        }
    }
}

fn mock_jwk_issuer(jwks: &[Jwk]) -> Mock {
    Mock::given(method("GET"))
        .and(path("/jwks_url"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            KeysResponse {
                keys: jwks.to_vec(),
            }
        )))
}

#[tokio::test]
async fn missing_kid() {
    let token_without_kid = load_scenario("missing_kid").token;
    let firebase_auth = firebase_auth();
    let decoded_token = Jwt::verify(&token_without_kid, &firebase_auth).await;

    let _desired_error = AuthError::InvalidJwt("Missing kid".to_string());

    assert!(decoded_token.is_err());
    assert!(matches!(decoded_token.err().unwrap(), _desired_error));
}

#[tokio::test]
// Test for when the JWK issuer return empty list
async fn missing_jwk() {
    let mock_server = setup_mock_server().await;
    let scenario = load_scenario("missing_jwk");

    // JWK issue returns empty list of jwks
    mock_jwk_issuer(Vec::new().as_slice())
        .expect(1)
        .mount(&mock_server)
        .await;

    let firebase_auth = firebase_auth();
    let decoded_token = Jwt::verify(&scenario.token, &firebase_auth).await;

    let _desired_error = AuthError::InvalidJwt("Missing Jwk".to_string());

    assert!(decoded_token.is_err());
    assert!(matches!(decoded_token.err().unwrap(), _desired_error))
}
