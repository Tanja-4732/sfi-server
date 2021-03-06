use crate::AppState;

use super::types::User;
use actix_web::{
    cookie::{Cookie, SameSite},
    get, post, web, App, HttpResponse, HttpServer, Responder,
};
use argonautica::{Hasher, Verifier};
use google_authenticator::GA_AUTH;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use libocc::Event;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    borrow::Borrow,
    ops::{Deref, DerefMut},
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

// TODO improve these constants
const SECRET_HASH_KEY: &'static str = "sneak 100";
const TOTP_DISCREPANCY: u64 = 1;

// A JWT should last five years
const DURATION: u64 = 5 * 365 * 24 * 60 * 60;

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(hello_auth)
        .service(handle_login)
        .service(handle_signup);
}

#[get("")]
async fn hello_auth() -> impl Responder {
    HttpResponse::Ok().body("Hello from the authentication API!")
}

#[post("/login")]
async fn handle_login(
    credentials: web::Json<UserLogin>,
    data: web::Data<AppState>,
) -> impl Responder {
    // Try to find the specified user
    if let Some(user) = {
        data.users
            .lock()
            .unwrap()
            .deref()
            .get_projection()
            .iter()
            .find(|u| u.uuid == credentials.uuid)
        // Drop the mutex lock here
    } {
        // Check credentials
        if validate_login(&credentials, &user) {
            // Authorize login
            HttpResponse::Ok()
                .cookie(
                    Cookie::build("jwt", make_jwt(&user))
                        .same_site(SameSite::Strict)
                        .secure(true)
                        .http_only(true)
                        .finish(),
                )
                .body(json!({
                    "uuid": user.uuid
                }))
        } else {
            // Deny login
            HttpResponse::Unauthorized().body(json!({
                "error": "Invalid credentials"
            }))
        }
    } else {
        // Report "no such user"
        HttpResponse::NotFound().body(json!({
            "error": "No such user"
        }))
    }
}

#[post("/signup")]
async fn handle_signup(
    credentials: web::Json<UserSignup>,
    data: web::Data<AppState>,
) -> impl Responder {
    // Make a new user
    let user = User::new(credentials.name.clone(), credentials.password.clone());

    // Try to insert into the event log
    let result = {
        data.users
            .lock()
            .unwrap()
            .deref_mut()
            .push(Event::create(user.clone()))
        // Drop the mutex lock here
    };

    // Check user creation result
    if result.is_ok() {
        // Generate JWT and send success
        HttpResponse::Ok().cookie(bake_cookie(&user)).body(json!({
            "uuid": user.uuid
        }))
    } else {
        // Deny registration
        HttpResponse::Unauthorized().body(json!({
            "error": "Couldn't create account"
        }))
    }
}

/// Generates the JWT authentication cookie
fn bake_cookie(user: &User) -> Cookie {
    Cookie::build("jwt", make_jwt(&user))
        .same_site(SameSite::Strict)
        .secure(true)
        .http_only(true)
        .finish()
}

pub fn validate_jwt() {
    todo!("Validate incoming JWTs placed on API requests")
}

// TODO move this into sfi-core
#[derive(Deserialize)]
struct UserSignup {
    name: String,
    password: String,
}

// TODO move this into sfi-core
#[derive(Deserialize)]
struct UserLogin {
    uuid: Uuid,
    password: String,
    totp: Option<String>,
}

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    nbf: usize,
    iat: usize,
}

fn make_jwt(user: &User) -> String {
    // Get the current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Make claims for the new JWT
    let claims = Claims {
        sub: user.uuid.to_string(),
        exp: (now + DURATION) as usize,
        nbf: now as usize,
        iat: now as usize,
    };

    // Encode, sign and return the new token
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("secret".as_ref()),
    )
    .unwrap()
}

/// Authenticates a user based on credentials
fn validate_login(credentials: &UserLogin, user: &User) -> bool {
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
pub fn make_salted_hash(password: String) -> String {
    Hasher::new()
        .with_password(&password)
        .with_secret_key(SECRET_HASH_KEY)
        .hash()
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use google_authenticator::{create_secret, get_code};

    const SUPER_SECRET_PASSWORD: &'static str = "123";

    #[test]
    fn test_validate_login_accept() {
        let totp_secret = create_secret!();

        // The user data stored on the server to validate against
        let mut user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned());
        user.totp_secret = Some(totp_secret.clone());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: user.uuid.clone(),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: Some(get_code!(&totp_secret).unwrap()),
        };

        // This login should work
        assert!(validate_login(&credentials, &user));
    }

    #[test]
    fn test_validate_login_accept_no_totp() {
        // The user data stored on the server to validate against
        let user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: user.uuid.clone(),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: None,
        };

        // This login should work
        assert!(validate_login(&credentials, &user));
    }

    #[test]
    fn test_validate_login_wrong_password() {
        let totp_secret = create_secret!();

        // The user data stored on the server to validate against
        let mut user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned());
        user.totp_secret = Some(totp_secret.clone());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: user.uuid.clone(),
            password: String::from("wrong password"),
            totp: Some(get_code!(&totp_secret).unwrap()),
        };

        // This login should not work
        assert!(!validate_login(&credentials, &user));
    }

    #[test]
    fn test_validate_login_missing_totp() {
        let totp_secret = create_secret!();

        // The user data stored on the server to validate against
        let mut user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned());
        user.totp_secret = Some(totp_secret.clone());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: user.uuid.clone(),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: None,
        };

        // This login should not work
        assert!(!validate_login(&credentials, &user));
    }

    #[test]
    fn test_validate_login_wrong_totp() {
        let totp_secret = create_secret!();

        // The user data stored on the server to validate against
        let mut user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned());
        user.totp_secret = Some(totp_secret.clone());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            uuid: user.uuid.clone(),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: Some(String::from("42")),
        };

        // This login should not work
        assert!(!validate_login(&credentials, &user));
    }
}
