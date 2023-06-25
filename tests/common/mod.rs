use rocket_firebase_auth::jwk::Jwk;
use serde::{Deserialize, Serialize};
use serde_json::json;
use wiremock::{
    matchers::{method, path},
    Mock,
    MockServer,
    ResponseTemplate,
};

pub static TEST_JWKS_URL: &str = "http://localhost:8888/jwks_url";

pub async fn setup_mock_server() -> MockServer {
    let listener = std::net::TcpListener::bind("localhost:8888").unwrap();
    MockServer::builder().listener(listener).start().await
}

#[derive(Debug, Serialize, Deserialize)]
struct MockJwksResponse {
    pub keys: Vec<Jwk>,
}

pub fn mock_jwk_issuer(jwks: &[Jwk]) -> Mock {
    Mock::given(method("GET"))
        .and(path("/jwks_url"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            MockJwksResponse {
                keys: jwks.to_vec()
            }
        )))
}
