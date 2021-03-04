pub mod v1;

use crate::constants;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::Serialize;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/v1").configure(v1::config))
        .route("", web::get().to(api_info));
}

async fn api_info() -> impl Responder {
    HttpResponse::Ok()
        .header("X-sfi-server-version", constants::meta::VERSION)
        .json2(&API_INFO)
}

#[derive(Clone, Serialize)]
struct ApiInfo<'a> {
    server_name: &'a str,
    server_version: &'a str,
    api_message: &'a str,
}

const API_INFO: ApiInfo = ApiInfo {
    server_name: constants::meta::NAME,
    server_version: constants::meta::VERSION,
    api_message: "Welcome to the sfi-server API!",
};
