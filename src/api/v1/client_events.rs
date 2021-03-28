//! This file handles API calls related to client-side event sourcing using sfi-core

use crate::state::AppState;
use actix_web::{get, web, HttpResponse, Responder};
use libocc::Timestamp;
use serde_json::json;
use sfi_core;
use std::ops::Deref;
use uuid::Uuid;

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(hello_events).service(handle_get_events_from);
}

#[get("")]
async fn hello_events(req: web::HttpRequest) -> impl Responder {
    let var_name = req.extensions();
    if let Some(uuid) = var_name.deref().get::<Uuid>() {
        let res_string = format!("Hello {:#?} from the events API!", uuid);

        HttpResponse::Ok().body(res_string)
    } else {
        HttpResponse::InternalServerError().finish().into_body()
    }
}

#[get("/{inventory_uuid}/{timestamp}")]
async fn handle_get_events_from(
    req: web::HttpRequest,
    web::Path((inventory_uuid, starting_date)): web::Path<(Uuid, Timestamp)>,
    data: web::Data<AppState<'_>>,
) -> impl Responder {
    if let Some(user_uuid) = req.extensions().deref().get::<Uuid>() {
        // Get a lock on the mutex
        let store_lock = data.inventories.lock().unwrap();
        let store = store_lock.deref();

        // Check if the inventory exists
        if let Some(inventory) = store.iter().find(|handle| *handle.uuid() == inventory_uuid) {
            // Check for permissions
            if inventory.allow_read(user_uuid) {
                // Return the event log
                HttpResponse::Ok().json2(&inventory.get_projector().get_events_from(&starting_date))
            } else {
                HttpResponse::Forbidden().body(json!({
                    "error": "Access denied (lacks read permission)"
                }))
            }
        } else {
            HttpResponse::NotFound().body(json!({
                "error": "No such inventory"
            }))
        }
    } else {
        HttpResponse::InternalServerError().finish().into_body()
    }
}
