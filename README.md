# rocket-firebase-auth

![status](https://github.com/Drpoppyseed/rocket-firebase-auth/actions/workflows/ci.yml/badge.svg)
[![crate](https://img.shields.io/crates/v/rocket-firebase-auth.svg)](https://crates.io/crates/rocket-firebase-auth)
[![codecov](https://img.shields.io/codecov/c/github/DrPoppyseed/rocket-firebase-auth)](https://codecov.io/gh/DrPoppyseed/rocket-firebase-auth)

Firebase Auth with Rocket, batteries included

- __Tiny__: `rocket-firebase-auth` is tiny, with features allowing you to make it even tinier
- __Does one thing well__: Encodes/decodes Firebase JWT tokens in Rocket apps, and that's it

## Getting started

### 1. Set Firebase service account keys as env variables

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

### 2. Create a `FirebaseAuth` instance and add to server state

Add `rocket-firebase-auth` to your project.

```toml
rocket_firebase_auth = "0.3.0"
```

Now, you can create a `FirebaseAuth` struct by reading the json file with a helper
function included with the default import.

```rust
use rocket::{routes, Build, Rocket};
use rocket_firebase_auth::{
    FirebaseAuth
};

struct ServerState {
    auth: FirebaseAuth
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
            auth: firebase_auth
        })
}
```

### 3. Verify the token from the endpoint function

On endpoints that we except to receive Authorization headers containing our encoded
Firebase tokens from the client, we can add a field to the endpoint function.
Running the `Jwt::verify()` function will decode the token, where you can get the
Firebase `uid`.

```rust
use rocket::{get, http::Status, routes, Build, Rocket, State};
use rocket_firebase_auth::{BearerToken, FirebaseAuth};

struct ServerState {
    auth: FirebaseAuth,
}

// Example function that returns an `Ok` and prints the verified user's uid.
// If the token is invalid, return with a `Forbidden` status code.
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
```

## Upgrading from v2 to v3

### 1. Switching to the builder pattern

In v3, by following Rust's builder pattern, we have a more fluent client builder.

__`try_from_env_with_filename` => `env_file`__

```rust
// v2 try_from_env_with_filename
let firebase_auth = FirebaseAuth::try_from_env_with_filename(
        ".env.test",
        "FIREBASE_CREDS",
    )
    .unwrap();
```

```rust
// v3 env_file
let firebase_auth = FirebaseAuth::builder()
    .env_file(
        ".env.test",
        "FIREBASE_CREDS",
    )
    .build()
    .unwrap();
```

__`try_from_env` => `env`__

```rust
// v2 try_from_env
let firebase_auth = FirebaseAuth::try_from_env(
        "FIREBASE_CREDS",
    )
    .unwrap();
```

```rust
// v3 env
let firebase_auth = FirebaseAuth::builder()
    .env("FIREBASE_CREDS")
    .build()
    .unwrap();
```

__`try_from_json_file` => `json_file`__

```rust
// v2 try_from_json_file
let firebase_auth = FirebaseAuth::try_from_json_file("tests/env_files/firebase-creds.json")
    .unwrap();
```

```rust
// v3 json_file
let firebase_auth = FirebaseAuth::builder()
    .json_file("firebase-creds.json")
    .build()
    .unwrap();
```

### 2. Changes to imports

We can change the imports for commonly used structs as follows

```rust
// v2
use rocket_firebase_auth::{
    auth::FirebaseAuth
    bearer_token::BearerToken
};
```

```rust
// v3
use rocket_firebase_auth::{
    FirebaseAuth,
    BearerToken
}
```

## Example project

For a more detailed example with a frontend example as well, checkout the [example
projects](https://github.com/DrPoppyseed/rocket-firebase-auth/tree/main/examples/react-rocket-example)
.

## Testing

To run tests, run the following command:

```bash
cargo test -- --test-threads=1
```

## Contribute

Any contributions (PRs, Issues) are welcomed!

## Questions

If you have any questions, however trivial it may seem, please let me know via Issues. I will respond!

## License

MIT
