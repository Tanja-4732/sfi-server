pub mod v1;

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

pub fn mount() -> actix_web::Scope {
    web::scope("/api").service(v1::build())
}
