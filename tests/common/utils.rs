use once_cell::sync::Lazy;
use rocket::serde::json::serde_json::json;
use rocket_firebase_auth::jwk::Jwk;
use serde::Deserialize;
use std::{collections::HashMap, fs};
use wiremock::{
    matchers::{method, path},
    Mock,
    MockServer,
    ResponseTemplate,
};

pub static TEST_JWKS_URL: &str = "http://localhost:8888/jwks_url";

#[derive(Debug, Deserialize)]
pub struct ScenarioFile {
    scenario: HashMap<String, Scenario>,
}

pub static SCENARIOS: Lazy<HashMap<String, Scenario>> = Lazy::new(|| {
    fs::read_to_string("./tests/scenarios.toml")
        .map(|contents| toml::from_str::<ScenarioFile>(&contents))
        .unwrap()
        .map(|file| {
            file.scenario.into_iter().fold(
                HashMap::new(),
                |mut accum, (key, scenario)| {
                    accum.insert(key, scenario);
                    accum
                },
            )
        })
        .unwrap()
});

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Scenario {
    pub desc:            Option<String>,
    pub token:           String,
    pub jwk_n:           String,
    pub kid:             String,
    pub rsa_public_key:  Option<String>,
    pub rsa_private_key: Option<String>,
}

pub async fn setup_mock_server() -> MockServer {
    let listener = std::net::TcpListener::bind("localhost:8888").unwrap();
    MockServer::builder().listener(listener).start().await
}

pub fn load_scenario(scenario_key: &str) -> Scenario {
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

pub fn mock_jwk_issuer(jwks: &[Jwk]) -> Mock {
    Mock::given(method("GET"))
        .and(path("/jwks_url"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!(jwks.to_vec())),
        )
}
