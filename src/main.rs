mod api;
mod constants;

use actix_files::{Files, NamedFile};
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Resource, Responder};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Print licence notice
    println!(
        "{}\n\n{}\n{}",
        constants::license::LICENSE_SHORT,
        constants::license::license_notice_title(),
        constants::license::license_notice_body()
    );

    HttpServer::new(|| {
        App::new()
            // Mount the API
            .service(api::mount())
            // Serve the static files of the frontend
            .service(Files::new("/", "../sfi-web/public/").index_file("index.html"))
            // Serve the index.html file on 404 (handle in the frontend itself)
            .default_service(web::get().to(serve_index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn serve_index() -> impl Responder {
    // println!("{:?}", std::env::current_dir());
    HttpResponse::Ok()
        .header("X-sfi-server-version", constants::meta::VERSION)
        .body(std::fs::read("../sfi-web/public/index.html").unwrap())
}
