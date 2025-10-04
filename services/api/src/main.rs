use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::HttpMessage;
use actix_web::dev::Service;
use actix_web::{App, HttpResponse, HttpServer, middleware::Logger, web};
use tracing_subscriber::EnvFilter;

mod error;
mod extractors;
mod middleware;
mod routes;
mod schemas;
mod state;
use state::{AppState, Settings};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let s = Settings::from_env();
    let db = db::connect(&s.database_url, 10).await.expect("db");
    db::migrate(&db).await.expect("migrations");

    let state = AppState {
        db: db.clone(),
        jwt: auth::JwtKeys::from_secret(&s.jwt_secret),
        access_ttl: s.access_ttl_seconds.unwrap_or(900),
        refresh_ttl: s.refresh_ttl_seconds.unwrap_or(60 * 60 * 24 * 7),
        cookie_domain: s.cookie_domain.unwrap_or_else(|| "localhost".into()),
        cookie_secure: s.cookie_secure.unwrap_or(false),
    };

    let governor_conf = GovernorConfigBuilder::default()
        .burst_size(10)
        .finish()
        .unwrap();

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_header()
            .allow_any_method();
        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(Governor::new(&governor_conf))
            .wrap(middleware::Csrf)
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(state.db.clone()))
            .service(routes::auth::register)
            .service(routes::auth::login)
            .service(routes::auth::refresh)
            .service(routes::auth::logout)
            .service(routes::items::list)
            .service(routes::items::get)
            .service(routes::items::create)
            .service(routes::items::update)
            .service(routes::items::remove)
            .default_service(web::to(|| async { HttpResponse::NotFound().finish() }))
            .wrap_fn(|req, srv| {
                // JWT auth extractor: read Bearer or cookie, set AuthUser ext if valid
                let jwt = req.app_data::<web::Data<AppState>>().unwrap().jwt.clone();
                let req_mut = req;
                let auth_header = req_mut
                    .headers()
                    .get("Authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let token_opt = if let Some(h) = auth_header {
                    h.strip_prefix("Bearer ").map(|s| s.to_string())
                } else {
                    None
                };
                let token = token_opt.or_else(|| {
                    req_mut
                        .cookie("access_token")
                        .map(|c| c.value().to_string())
                });
                if let Some(tok) = token {
                    if let Ok(claims) = auth::verify(&jwt, &tok) {
                        req_mut
                            .extensions_mut()
                            .insert(crate::extractors::AuthUser {
                                user_id: claims.sub,
                                role: claims.role,
                            });
                    }
                }
                srv.call(req_mut)
            })
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
