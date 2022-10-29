use std::{env, str::FromStr};

use dotenvy::dotenv;
use rocket::{Build, Rocket};
use rocket_cors::{AllowedOrigins, CorsOptions};
use rocket_firebase_auth::firebase_auth::{FirebaseAdmin, FirebaseAuth};

mod api;

#[derive(Debug)]
pub struct ServerState {
    pub auth: FirebaseAuth,
}

#[rocket::launch]
async fn rocket() -> Rocket<Build> {
    // Setup dotenv to read env variables
    dotenv().ok();
    let firebase_admin_certs = env::var("FIREBASE_ADMIN_CERTS").expect(
        "Failed to retrieve environment variable `FIREBASE_ADMIN_CERTS`",
    );
    let firebase_admin =
        serde_json::from_str::<FirebaseAdmin>(&firebase_admin_certs)
            .expect("Failed to deserialize value for `FIREBASE_ADMIN_CERTS`");

    let firebase_auth = FirebaseAuth::with_firebase_admin(firebase_admin);

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
