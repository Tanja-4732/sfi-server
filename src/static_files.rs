use actix_files::Files;
use actix_web::web;

pub fn config(cfg: &mut web::ServiceConfig) {
    // Serve the static files of the frontend
    cfg.service(Files::new("/", "../sfi-web/public/").index_file("index.html"));
}
