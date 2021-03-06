use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::authentication::make_salted_hash;

// TODO add better methods (get/set/constructor)
#[derive(Deserialize, Serialize, Clone)]
pub struct User {
    pub uuid: Uuid,
    pub name: String,
    pub pwd_salt_hash: String,
    pub totp_secret: Option<String>,
}

impl User {
    pub fn new(name: String, password: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name,
            pwd_salt_hash: make_salted_hash(password),
            totp_secret: None,
        }
    }
}

// Implemented manually to distinguish between users based on their UUIDs
impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}
