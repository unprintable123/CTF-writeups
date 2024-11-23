mod aead;
mod login_system;

use actix_web::{web, App, HttpServer};
use tera::Tera;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use rand::Rng;
use login_system::{UserStore, register, login, users, index, init_server_admin, recover_account, users_page};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // If you want debug info in local, uncomment the following two lines
    // std::env::set_var("RUST_LOG", "debug");
    // env_logger::init();
    let user_store: UserStore = Arc::new(Mutex::new(HashMap::new()));
    let recovered_times: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let mut super_pwd: [u8; 32] = [0u8; 32];
    // rand ascii
    let mut rng = rand::thread_rng();
    for i in 0..32 {
        super_pwd[i] = rng.gen_range(33..126);
    }
    let super_pwd_str = String::from_utf8_lossy(&super_pwd);
    let tera = match Tera::new("templates/**/*") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            std::process::exit(1);
        }
    };

    // set the admin user
    init_server_admin(&super_pwd_str, &user_store);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Arc::clone(&user_store)))
            .app_data(web::Data::new(Arc::clone(&recovered_times)))
            .app_data(web::Data::new(tera.clone()))
            .route("/", web::get().to(index))
            .route("/users.html", web::get().to(users_page))
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/users", web::get().to(users))
            .route("/recover", web::post().to(recover_account))
            .service(actix_files::Files::new("/static", "static").show_files_listing())
    })
    .bind("0.0.0.0:21111")?
    .run()
    .await
}