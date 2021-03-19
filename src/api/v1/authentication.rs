use super::types::User;
use crate::AppState;
use actix_web::{
    cookie::{Cookie, SameSite},
    get, post, web, HttpMessage, HttpResponse, Responder,
};
use anyhow::anyhow;
use anyhow::Result;
use argonautica::{Hasher, Verifier};
use google_authenticator::GA_AUTH;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use libocc::Event;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sfi_core::users::{UserIdentifier, UserInfo, UserLogin, UserSignup};
use std::{
    borrow::Cow,
    ops::{Deref, DerefMut},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

// TODO improve these constants
const SECRET_HASH_KEY: &'static str = "sneak 100";
const TOTP_DISCREPANCY: u64 = 1;
const JWT_SECRET: &'static str = "sneak 100";
const USE_SECURE_COOKIE: bool = false;

// A JWT should last five years
const DURATION: u64 = 5 * 365 * 24 * 60 * 60;

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(hello_auth)
        .service(handle_login)
        .service(handle_status)
        .service(handle_logout)
        .service(handle_signup);
}

#[get("")]
async fn hello_auth() -> impl Responder {
    HttpResponse::Ok().body("Hello from the authentication API!")
}

#[post("/login")]
async fn handle_login(
    credentials: web::Json<UserLogin>,
    data: web::Data<AppState<'_>>,
) -> impl Responder {
    // Get a lock on the mutex
    let lock = data.users.lock().unwrap();

    if let Some(user) = {
        let mut user_iter = lock.deref().get_projection().iter();

        // Try to find the specified user
        match &credentials.identifier {
            UserIdentifier::Name(name) => user_iter.find(|u| u.name == *name),
            UserIdentifier::Uuid(uuid) => user_iter.find(|u| u.uuid == *uuid),
        }
    } {
        // Check credentials
        if validate_login(&credentials, &user) {
            // Authorize login
            HttpResponse::Ok()
                .cookie(bake_cookie(&user))
                .json(make_json_info(&user))
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
    data: web::Data<AppState<'_>>,
) -> impl Responder {
    // Make a new user
    if let Ok(user) = User::new(credentials.name.clone(), credentials.password.clone()) {
        let result = {
            // Lock the mutex
            let mut projector = data.users.lock().unwrap();

            // Check for a name collision
            if resolve_name(&credentials.name, projector.deref().get_projection()).is_some() {
                Err(anyhow!("Name taken"))
            } else {
                // Try to insert into the event log
                projector
                    .deref_mut()
                    // TODO reorganize and replace clone with move
                    .push(Event::create(Cow::Owned(user.clone())))
            }
            // Drop the mutex lock here
        };

        // Check user creation result
        if result.is_ok() {
            // Generate JWT and send success
            HttpResponse::Ok()
                .cookie(bake_cookie(&user))
                .json(make_json_info(&user))
        } else {
            // Deny registration
            HttpResponse::BadRequest().body(json!({
                "error": "Couldn't create account"
            }))
        }
    } else {
        // Deny registration
        HttpResponse::BadRequest().body(json!({
            "error": "Need a password"
        }))
    }
}

#[get("/status")]
async fn handle_status(data: web::Data<AppState<'_>>, req: web::HttpRequest) -> impl Responder {
    // Get the JWT cookie (if any)
    if let Some(jwt_cookie) = req.cookie("jwt") {
        // Validate the JWT
        if let Ok(uuid) = extract_uuid_from_jwt(jwt_cookie.value()) {
            // Valid JWT, find user in projection
            if let Some(user) = {
                data.users
                    .lock()
                    .unwrap()
                    .deref()
                    .get_projection()
                    .iter()
                    .find(|user| user.uuid == uuid)
                // Drop the mutex lock here
            } {
                // Inform the user about their login status
                HttpResponse::Ok().json(make_json_info(&user))
            } else {
                // Report the missing entry in the projection
                HttpResponse::InternalServerError().body(json!({
                    "error": "Couldn't find user in projection"
                }))
            }
        } else {
            // Invalid JWT
            HttpResponse::Unauthorized().body(json!({
                "error": "Invalid credentials"
            }))
        }
    } else {
        // No JWT present
        HttpResponse::Ok().body(json!({
            "status": "Not logged in"
        }))
    }
}

#[get("/logout")]
async fn handle_logout(req: web::HttpRequest) -> impl Responder {
    // Check for a JWT cookie
    if let Some(_) = req.cookie("jwt") {
        // Remove the cookie
        HttpResponse::Ok()
            .cookie(Cookie::build("jwt", "").path("/").finish())
            .body(json!({
                "status": "Logged out"
            }))
    } else {
        // No JWT present
        HttpResponse::BadRequest().body(json!({
            "status": "Wasn't logged in"
        }))
    }
}

fn make_json_info(user: &User) -> UserInfo {
    UserInfo {
        uuid: user.uuid.clone(),
        name: user.name.clone(),
    }
}

/// Generates the JWT authentication cookie
fn bake_cookie(user: &User) -> Cookie {
    Cookie::build("jwt", make_jwt(&user))
        .same_site(SameSite::Strict)
        .secure(USE_SECURE_COOKIE)
        .http_only(true)
        .permanent()
        .path("/")
        .finish()
}

/// Extracts the UUID from a JWT (and validates it)
pub fn extract_uuid_from_jwt(token: &str) -> Result<Uuid> {
    Uuid::from_str(
        &decode::<Claims>(
            token,
            &DecodingKey::from_secret(JWT_SECRET.as_ref()),
            &Validation::new(Algorithm::HS256),
        )?
        .claims
        .sub,
    )
    .map_err(|uuid_error| anyhow::Error::from(uuid_error))
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
        &EncodingKey::from_secret(JWT_SECRET.as_ref()),
    )
    .unwrap()
}

/// Authenticates a user based on credentials
fn validate_login(credentials: &UserLogin, user: &User) -> bool {
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
pub fn make_salted_hash(password: String) -> Result<String, argonautica::Error> {
    Hasher::new()
        .with_password(&password)
        .with_secret_key(SECRET_HASH_KEY)
        .hash()
}

/// Resolves a name to a user instance
pub fn resolve_name<'a>(
    name: &'a str,
    projection: &'a Vec<Cow<User>>,
) -> Option<&'a Cow<'a, User>> {
    projection.iter().find(|u| u.name == name)
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
        let mut user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned()).unwrap();
        user.totp_secret = Some(totp_secret.clone());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            identifier: UserIdentifier::Uuid(user.uuid.clone()),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: Some(get_code!(&totp_secret).unwrap()),
        };

        // This login should work
        assert!(validate_login(&credentials, &user));
    }

    #[test]
    fn test_validate_login_accept_no_totp() {
        // The user data stored on the server to validate against
        let user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned()).unwrap();

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            identifier: UserIdentifier::Uuid(user.uuid.clone()),
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
        let mut user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned()).unwrap();
        user.totp_secret = Some(totp_secret.clone());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            identifier: UserIdentifier::Uuid(user.uuid.clone()),
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
        let mut user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned()).unwrap();
        user.totp_secret = Some(totp_secret.clone());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            identifier: UserIdentifier::Uuid(user.uuid.clone()),
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
        let mut user = User::new("someone".to_owned(), SUPER_SECRET_PASSWORD.to_owned()).unwrap();
        user.totp_secret = Some(totp_secret.clone());

        // The credentials to attempt authentication with
        let credentials = UserLogin {
            identifier: UserIdentifier::Uuid(user.uuid.clone()),
            password: SUPER_SECRET_PASSWORD.to_owned(),
            totp: Some(String::from("42")),
        };

        // This login should not work
        assert!(!validate_login(&credentials, &user));
    }
}
