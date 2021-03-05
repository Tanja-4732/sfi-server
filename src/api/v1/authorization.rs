//! This file generates & validates JSON web tokens

use super::types::UserData;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    nbf: usize,
    iat: usize,
}

// A JWT should last five years
const DURATION: u64 = 5 * 365 * 24 * 60 * 60;

fn make_jwt(user: &UserData) -> String {
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
