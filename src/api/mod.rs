//! This is the sfi-server API. It contains the various API versions

pub mod v1;

use crate::constants;
use actix_web::{get, web, HttpResponse, Responder};
use serde_json::json;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(api_info)
        .service(web::scope("/v1").configure(v1::config));
}

#[get("")]
async fn api_info() -> impl Responder {
    HttpResponse::Ok()
        .header("X-sfi-server-version", constants::meta::VERSION)
        .body(json!({
            "server_name": constants::meta::NAME,
            "server_version": constants::meta::VERSION,
            "api_message": "Welcome to the sfi-server API!",
        }))
}
