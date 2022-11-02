# rocket-firebase-auth

![status](https://github.com/Drpoppyseed/rocket-firebase-auth/actions/workflows/ci.yml/badge.svg)
[![crate](https://img.shields.io/crates/v/rocket-firebase-auth.svg)](https://crates.io/crates/rocket-firebase-auth)
[![codecov](https://img.shields.io/codecov/c/github/DrPoppyseed/rocket-firebase-auth)](https://codecov.io/gh/DrPoppyseed/rocket-firebase-auth)

Firebase Auth with Rocket, batteries included

- __Tiny__: `rocket-firebase-auth` is tiny, with features allowing you to make it even tinier
- __Does one thing well__: Encodes/decodes Firebase JWT tokens in Rocket apps, and that's it

## Getting started

#### 1. Set Firebase service account keys as env variables

If you haven't already, create a service account in Firebase for the Rocket backend
you are creating. Generate a new private key and copy-paste the generated json
into a `firebase-credentials.json` file.

```json
{
  "type": "*********",
  "project_id": "***********",
  "private_key_id": "*************",
  "private_key": "*****************",
  "client_email": "*********",
  "client_id": "*******",
  "auth_uri": "********",
  "token_uri": "********",
  "auth_provider_x509_cert_url": "********",
  "client_x509_cert_url": "********"
} 
```

Don't forget to add the `firebase-credentials.json` file to your `.gitignore`.

```gitignore
# Firebase service account's secret credentials
firebase-credentials.json
```

#### 2. Create a `FirebaseAuth` instance and add to server state

Add `rocket-firebase-auth` to your project.

```toml
rocket_firebase_auth = "0.2.4"
```

Now, you can create a `FirebaseAuth` struct by reading the json file with a helper
function included with the default import.

```rust
use rocket::{routes, Build, Rocket};
use rocket_firebase_auth::{
    auth::FirebaseAuth
};

struct ServerState {
    pub auth: FirebaseAuth
}

#[rocket::launch]
async fn rocket() -> Rocket<Build> {
    let firebase_auth = FirebaseAuth::try_from_json_file("firebase-credentials.json")
        .expect("Failed to read Firebase credentials");

    rocket::build()
        .mount("/", routes![hello_world])
        .manage(ServerState {
            auth: firebase_auth
        })
}
```

#### 3. Verify the token from the endpoint function

On endpoints that we except to receive Authorization headers containing our encoded
Firebase tokens from the client, we can add a field to the endpoint function.
Running the `Jwt::verify()` function will decode the token, where you can get the
Firebase `uid`.

```rust
use futures::TryFutureExt;
use rocket::{get, http::Status, routes, Build, Rocket, State};
use rocket_firebase_auth::{
    auth::FirebaseAuth,
    bearer_token::BearerToken,
};

struct ServerState {
    pub auth: FirebaseAuth,
}

// Example function that returns an `Ok` and prints the verified user's uid.
// If the token is invalid, return with a `Forbidden` status code.
#[get("/")]
async fn hello_world(state: &State<ServerState>, token: BearerToken) -> Status {
    match state
        .auth
        .verify(&token)                            // verify token
        .map_ok(|decoded_token| decoded_token.uid) // extract uid from decoded token
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
```

## Example project

For a more detailed example with a frontend example as well, checkout the [example
projects](https://github.com/DrPoppyseed/rocket-firebase-auth/tree/main/examples/react-rocket-example)
.

## Contribute

Any contributions (PRs, Issues) are welcomed!

## License

MIT