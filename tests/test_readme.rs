#[cfg(feature = "rocket")]
use rocket::{get, http::Status, routes, Build, Rocket, State};
#[cfg(feature = "rocket")]
use rocket_firebase_auth::{BearerToken, FirebaseAuth};

#[cfg(feature = "rocket")]
struct ServerState {
    auth: FirebaseAuth,
}

// Example function that returns an `Ok` and prints the verified user's uid.
// If the token is invalid, return with a `Forbidden` status code.
#[cfg(feature = "rocket")]
#[get("/")]
async fn hello_world(state: &State<ServerState>, token: BearerToken) -> Status {
    let token = state.auth.verify(&token).await; // verify token

    match token // extract uid from decoded token
    {
        Ok(token) => {
            println!("Authentication succeeded with uid={}", token.uid);
            Status::Ok
        }
        Err(_) => {
            println!("Authentication failed.");
            Status::Forbidden
        }
    }
}

#[cfg(feature = "rocket")]
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
