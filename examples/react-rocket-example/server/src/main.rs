use rocket::{Build, Rocket};
use rocket_cors::{AllowedOrigins, CorsOptions};
use rocket_firebase_auth::auth::FirebaseAuth;
use std::str::FromStr;

mod api;

#[derive(Debug)]
pub struct ServerState {
    pub auth: FirebaseAuth,
}

#[rocket::launch]
async fn rocket() -> Rocket<Build> {
    let firebase_auth = FirebaseAuth::try_from_json_file("firebase-certs.json")
        .expect("Failed to read firebase credentials");

    // Setup cors
    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::all())
        .allowed_methods(
            ["Get", "Post", "Put", "Delete", "Options"]
                .iter()
                .map(|s| FromStr::from_str(s).unwrap())
                .collect(),
        )
        .allow_credentials(true)
        .to_cors()
        .expect("Failed to setup cors configuration.");

    rocket::build()
        .mount("/", api::routes())
        .mount("/", rocket_cors::catch_all_options_routes())
        .attach(cors.clone())
        .manage(cors)
        .manage(ServerState {
            auth: firebase_auth,
        })
}
