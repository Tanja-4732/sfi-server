//! This is the first version of the sfi-server API

pub mod authentication;
pub mod authorization;
pub mod events;

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(hello_api);
}

#[get("")]
async fn hello_api() -> impl Responder {
    HttpResponse::Ok().body("Hello from the API!")
}
