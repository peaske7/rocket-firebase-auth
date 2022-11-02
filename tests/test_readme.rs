use futures::TryFutureExt;
use rocket::{get, http::Status, routes, Build, Rocket, State};
use rocket_firebase_auth::{
    bearer_token::BearerToken,
    firebase_auth::FirebaseAuth,
};

struct ServerState {
    pub auth: FirebaseAuth,
}

#[get("/")]
async fn hello_world(state: &State<ServerState>, token: BearerToken) -> Status {
    match state
        .auth
        .verify(&token)
        .map_ok(|decoded_token| decoded_token.uid)
        .await
    {
        Ok(uid) => {
            println!("Authentication succeeded with uid={uid}");
            Status::Ok
        }
        Err(_) => {
            println!("Authentication failed.");
            Status::Forbidden
        }
    }
}

#[rocket::launch]
async fn rocket() -> Rocket<Build> {
    let firebase_auth =
        FirebaseAuth::try_from_json_file("firebase-credentials.json")
            .expect("Failed to read Firebase credentials");

    rocket::build()
        .mount("/", routes![hello_world])
        .manage(ServerState {
            auth: firebase_auth,
        })
}
