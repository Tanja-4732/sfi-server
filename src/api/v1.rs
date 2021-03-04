use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

pub fn build() -> actix_web::Scope {
    web::scope("/").service(hello_api)
}

#[get("")]
async fn hello_api() -> impl Responder {
    HttpResponse::Ok().body("Hello from the API!")
}
