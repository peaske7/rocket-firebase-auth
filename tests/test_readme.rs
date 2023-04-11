use rocket::{get, routes, Build, Rocket};
use rocket_firebase_auth::{FirebaseAuth, FirebaseToken};

struct ServerState {
    auth: FirebaseAuth,
}

// Example function that returns an `Ok` and prints the verified user's uid.
// If the token is invalid, return with a `Forbidden` status code.
// No need to implement the logic on your own, including the guard is enough
#[get("/")]
async fn handler(guard: FirebaseToken) -> String {
    // Including the FirebaseToken guard is enough
    // the handler will run only if the token is valid.
    // The request guard won't work if FirebaseAuth state is not present. 
    format!("Hello, you're logged in as user ID {}", guard.sub)
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
