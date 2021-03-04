use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use argonautica::{Hasher, Verifier};
use google_authenticator::{create_secret, get_code};
use google_authenticator::{verify_code, GA_AUTH};
use serde::Deserialize;
use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

// TODO improve these constants
const SUPER_SECRET_PASSWORD: &'static str = "123";
const USER_UUID: &'static str = "7a7e9c87-d745-4919-8343-9d44cf7de2eb";
const SECRET_HASH_KEY: &'static str = "sneak 100";
const TOTP_DISCREPANCY: u64 = 1;

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(hello_auth).service(handle_login);
}

#[get("")]
async fn hello_auth() -> impl Responder {
    HttpResponse::Ok().body("Hello from the authentication API!")
}

#[post("/login")]
async fn handle_login(credentials: web::Json<UserLogin>) -> impl Responder {
    HttpResponse::Ok().body(format!("You are {}", credentials.uuid))
}

#[derive(Deserialize)]
struct UserLogin {
    uuid: Uuid,
    password: String,
    totp: Option<String>,
}

struct UserData {
    uuid: Uuid,
    pwd_salt_hash: String,
    totp_secret: Option<String>,
}

/// Authenticates a user based on credentials
fn validate_login(credentials: &UserLogin, user: &UserData) -> bool {
    // Make sure to authenticate the correct user
    if credentials.uuid != user.uuid {
        return false;
    }

    // Check if a TOTP exists
    if let Some(secret) = &user.totp_secret {
        // If a TOTP secret is present, check for a valid TOTP code
        if let Some(code) = &credentials.totp {
            if !GA_AUTH.verify_code(secret, code, TOTP_DISCREPANCY, 0) {
                // If the code doesn't match within the specified discrepancy window
                return false;
            }
        } else {
            // If a TOTP secret is configured, but no TOTP code was provided
            return false;
        }
    }

    // Validate salted & hashed password
    Verifier::new()
        .with_hash(user.pwd_salt_hash.clone())
        .with_password(credentials.password.clone())
        .with_secret_key(SECRET_HASH_KEY)
        .verify()
        .unwrap_or(false)
}

/// Generates some nice salt
fn make_salted_hash(password: &'static str) -> String {
    Hasher::new()
        .with_password(password)
        .with_secret_key(SECRET_HASH_KEY)
        .hash()
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_validate_login_accept() {
        let totp_secret = create_secret!();

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: Uuid::from_str(USER_UUID).unwrap(),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: Some(get_code!(&totp_secret).unwrap()),
        };

        // The user data stored on the server to validate against
        let user = UserData {
            uuid: Uuid::from_str(USER_UUID).unwrap(),
            pwd_salt_hash: make_salted_hash(SUPER_SECRET_PASSWORD),
            totp_secret: Some(totp_secret),
        };

        // This login should work
        assert!(validate_login(&credentials, &user));
    }

    #[test]
    fn test_validate_login_wrong_password() {
        let totp_secret = create_secret!();

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: Uuid::from_str(USER_UUID).unwrap(),
            password: String::from("wrong password"),
            totp: Some(get_code!(&totp_secret).unwrap()),
        };

        // The user data stored on the server to validate against
        let user = UserData {
            uuid: Uuid::from_str(USER_UUID).unwrap(),
            pwd_salt_hash: make_salted_hash(SUPER_SECRET_PASSWORD),
            totp_secret: Some(totp_secret),
        };

        // This login should not work
        assert!(!validate_login(&credentials, &user));
    }

    #[test]
    fn test_validate_login_missing_totp() {
        let totp_secret = create_secret!();

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: Uuid::from_str(USER_UUID).unwrap(),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: None,
        };

        // The user data stored on the server to validate against
        let user = UserData {
            uuid: Uuid::from_str(USER_UUID).unwrap(),
            pwd_salt_hash: make_salted_hash(SUPER_SECRET_PASSWORD),
            totp_secret: Some(totp_secret),
        };

        // This login should not work
        assert!(!validate_login(&credentials, &user));
    }

    #[test]
    fn test_validate_login_wrong_totp() {
        let totp_secret = create_secret!();

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: Uuid::from_str(USER_UUID).unwrap(),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: Some(String::from("42")),
        };

        // The user data stored on the server to validate against
        let user = UserData {
            uuid: Uuid::from_str(USER_UUID).unwrap(),
            pwd_salt_hash: make_salted_hash(SUPER_SECRET_PASSWORD),
            totp_secret: Some(totp_secret),
        };

        // This login should not work
        assert!(!validate_login(&credentials, &user));
    }
}
