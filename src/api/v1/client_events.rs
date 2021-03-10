//! This file handles API calls related to client-side event sourcing using sfi-core

use sfi_core;

use actix_web::{get, web, HttpResponse, Responder};

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(hello_events);
}

#[get("")]
async fn hello_events() -> impl Responder {
    HttpResponse::Ok().body("Hello from the events API!")
}
