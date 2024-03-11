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
into a `firebase-credentials.json` file. It should look something like the json snippet below.

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

### 2. Setup `FirebaseAuth` and get started

Add `rocket-firebase-auth` to your project.

```toml
rocket_firebase_auth = "0.5"
```

Now, you can create a `FirebaseAuth` struct by reading the json file with a helper
function included with the default import.

```rust
use rocket::{get, http::Status, routes, Build, Rocket};
use rocket_firebase_auth::{FirebaseAuth, FirebaseToken};

// Setup the server state, which will include your FirebaseAuth instance, among
// other things like the connection pool to your database.
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
```

## Example projects

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
