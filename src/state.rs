use crate::api::v1::types::User;
use actix_web::web;
use anyhow::Result;
use lazy_static::lazy_static;
use libocc::events::Projector;
use serde::{Deserialize, Serialize};
use sfi_core::events::store::Store;
use std::{fmt::format, fs, sync::Mutex};

fn get_pwd() -> String {
    std::env::current_dir()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

lazy_static! {
    static ref DATA_PATH: String = get_pwd() + "/data";
    static ref USERS_PATH: String = DATA_PATH.clone() + "/users.json";
    static ref STORE_PATH: String = DATA_PATH.clone() + "/store.json";
}

#[derive(Serialize, Deserialize)]
pub struct AppState<'a> {
    pub users: Mutex<Projector<'a, User>>,
    pub inventories: Mutex<Store<'a>>,
}

/// Reads the stored states from disk (if available) or creates new ones otherwise
pub fn get_app_state<'a>() -> web::Data<AppState<'a>> {
    // Make sure the directory exists
    fs::create_dir_all(DATA_PATH.clone())
        .expect(&(String::from("Cannot guarantee existence of directory ") + &DATA_PATH));

    // Try to load the users
    let users: Mutex<Projector<'a, User>> = Mutex::new(
        serde_json::from_str(
            &fs::read_to_string(USERS_PATH.clone()).unwrap_or("make-new".to_owned()),
        )
        .unwrap_or(Projector::new()),
    );

    // Try to load the event store
    let inventories: Mutex<Store> = Mutex::new(
        serde_json::from_str(
            &fs::read_to_string(STORE_PATH.clone()).unwrap_or("make-new".to_owned()),
        )
        .unwrap_or(Store::new()),
    );

    // Return the loaded data
    web::Data::new(AppState { users, inventories })
}

/// Serialize & persist the event store
pub fn persist_store<'a>(store: &Store<'a>) -> Result<()> {
    Ok(
        fs::write(STORE_PATH.clone(), serde_json::to_string_pretty(&store)?)
            .expect("Cannot write to store.json"),
    )
}

/// Serialize & persist the user store
pub fn persist_users<'a>(users: &Projector<'a, User>) -> Result<()> {
    Ok(
        fs::write(USERS_PATH.clone(), serde_json::to_string_pretty(&users)?)
            .expect("Cannot write to users.json"),
    )
}
