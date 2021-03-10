//! This file handles API calls related to client-side event sourcing using sfi-core

use std::ops::Deref;

use sfi_core;

use actix_web::{get, web, HttpResponse, Responder};
use uuid::Uuid;

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(hello_events);
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
