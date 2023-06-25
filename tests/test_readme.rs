#![allow(dead_code)]
use rocket::{get, http::Status, routes, Build, Rocket};
use rocket_firebase_auth::{FirebaseAuth, FirebaseToken};

struct ServerState {
    auth: FirebaseAuth,
}

#[get("/")]
async fn hello_world(token: FirebaseToken) -> Status {
    println!("Authentication succeeded with uid={}", token.sub);
    Status::Ok
}

#[rocket::launch]
async fn rocket() -> Rocket<Build> {
    let firebase_auth = FirebaseAuth::builder()
        .json_file("firebase-credentials.json")
        .build()
        .unwrap();

    rocket::build()
        .mount("/", routes![hello_world])
        .manage(ServerState {
            auth: firebase_auth,
        })
}
