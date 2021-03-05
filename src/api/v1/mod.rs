//! This is the first version of the sfi-server API

mod authentication;
mod authorization;
mod client_events;
mod server_events;
mod types;

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(hello_api)
        .service(web::scope("/authentication").configure(authentication::config));
}

#[get("")]
async fn hello_api() -> impl Responder {
    HttpResponse::Ok().body("Hello from the API v1!")
}
