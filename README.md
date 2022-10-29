# rocket-firebase-auth

![status](https://github.com/Drpoppyseed/rocket-firebase-auth/actions/workflows/ci.yml/badge.svg)
[![codecov](https://img.shields.io/codecov/c/github/DrPoppyseed/rocket-firebase-auth)](https://codecov.io/gh/DrPoppyseed/rocket-firebase-auth)

Encode/decode Firebase tokens in Rocket apps with ease.

## Getting started

### 1. Set Firebase service account keys as env variables

If you haven't already, create a service account for the Rocket server you are
adding firebase to. Generate a new private key and copy paste the generated json
into a `.env` file.

```dotenv
FIREBASE_ADMIN_CERTS='{ "type": "service_account", ... }'
```

### 2. Create a `FirebaseAuth` instance by reading the env variable

You can create a `FirebaseAuth` struct by deserializing the env string that we set
into `FirebaseAdmin` struct and call the `FirebaseAuth::with_firebase_admin()`
function.

```rust
dotenv().ok();
let firebase_admin_certs = env::var("FIREBASE_ADMIN_CERTS").unwrap();
let firebase_admin = serde_json::from_str::<FirebaseAdmin>( & firebase_admin_certs)
.unwrap();
let firebase_auth = FirebaseAuth::with_firebase_admin(firebase_admin);
```

### 3. Add `FirebaseAuth` to the managed server state in Rocket

In order to access the `FirebaseAuth` instance from our endpoint functions, add
it to the server state.

```rust
pub struct ServerState {
    pub auth: FirebaseAuth
}

#[rocket::launchj]
async fn rocket() -> Rocket<Build> {
    dotenv().ok();
    let firebase_admin_certs = env::var("FIREBASE_ADMIN_CERTS").unwrap();
    let firebase_admin = serde_json::from_str::<FirebaseAdmin>(&firebase_admin_certs)
        .unwrap();
    let firebase_auth = FirebaseAuth::with_firebase_admin(firebase_admin);

    rocket::build()
        .mount("/", routes![...])
        .manage(ServerState {
            auth: firebase_auth
        })
}
```

### 4. Verify the token from the endpoint function

On endpoints that we except to receive Authorization headers containing our encoded
Firebase tokens from the client, we can add a field to the endpoint function.
Running the `Jwt::verify()` function will decode the token, where you can get the
Firebase `uid`.

```rust
#[get("/")]
async fn hello_world(
    state: &State<ServerState>,
    token: BearerToken,
) -> status::Accepted<String> {
    let uid = Jwt::verify(&token.0, &state.auth)
        .map_ok(|decoded_token| decoded_token.claims.sub)
        .await
        .unwrap();

    status::Accepted(Some(format!("uid: {uid}")))
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