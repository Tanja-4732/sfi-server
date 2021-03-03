mod api;

use actix_files::{Files, NamedFile};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Resource, Responder};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(api::mount())
            .service(echo)
            .route("/hey", web::get().to(manual_hello))
            .service(Files::new("/", "../sfi-web/public/").index_file("index.html"))
            .default_service(web::get().to(serve_index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    println!("{:?}", std::env::current_dir());
    HttpResponse::Ok().body("Hey there!")
}

// async fn serve_index() -> impl Responder {
//     println!("{:?}", std::env::current_dir());
//     HttpResponse::Ok().body("index.html goes here")
// }

async fn serve_index() -> impl Responder {
    println!("{:?}", std::env::current_dir());
    HttpResponse::Ok().body(std::fs::read("../sfi-web/public/index.html").unwrap())
}
