use uuid::Uuid;

// TODO add better methods (get/set/constructor)
pub struct UserData {
    pub uuid: Uuid,
    pub pwd_salt_hash: String,
    pub totp_secret: Option<String>,
}
