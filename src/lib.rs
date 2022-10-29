//! Encode/decode Firebase tokens in Rocket apps with ease
//!
//! # Description
//!
//! `rocket-firebase-auth` is a plug-and-play, batteries included firebase auth
//! library that handles the encoding/decoding of Firebase tokens on Rocket
//! servers.
//! The library is built primarily for backends that use Firebase tokens as a
//! means of authentication from the client.
//!
//! # Features
//!
//! `rocket-firebase-auth` has two features:
//!
//! `env`: Includes functions that helps in initializing Firebase Auth from dotenv files
//!
//! `encode`: Adds support for encoding tokens
//!
#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]
pub mod bearer_token;
pub mod errors;
pub mod firebase_auth;
pub mod jwk;
pub mod jwt;
pub mod rocket;
