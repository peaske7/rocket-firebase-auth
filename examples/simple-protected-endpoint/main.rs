#[macro_use]
extern crate rocket;
use rocket_firebase_auth::{FirebaseAuth, FirebaseToken};

#[launch]
async fn rocket() -> _ {
    let firebase_auth = FirebaseAuth::builder()
        .json_file("firebase_creds.json") // make sure this file exists
        .build()
        .unwrap();

    rocket::build()
        .manage(firebase_auth) // Add FirebaseAuth as a managed service
        .mount("/", routes![handler])
}

#[get("/")]
async fn handler(guard: FirebaseToken) -> String {
    // Including the FirebaseToken guard is enough
    // the handler will run only if the token is valid.
    // The request guard won't work if FirebaseAuth state is not present. 
    format!("Hello, you're logged in as user ID {}", guard.sub)
}