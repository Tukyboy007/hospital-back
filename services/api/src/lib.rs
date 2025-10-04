pub mod error;
pub mod extractors;
pub mod routes;
pub mod schemas;
pub mod state;

use actix_web::{App, web};

pub fn create_app(
    state: state::AppState,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .app_data(web::Data::new(state))
        .service(routes::auth::register)
        .service(routes::auth::login)
        .service(routes::auth::refresh)
        .service(routes::auth::logout)
}
