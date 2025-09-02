use actix_web::{FromRequest, HttpMessage};
use std::future::{Ready, ready};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub role: i32,
}

impl FromRequest for AuthUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        if let Some(ext) = req.extensions().get::<AuthUser>() {
            return ready(Ok(ext.clone()));
        }
        ready(Err(actix_web::error::ErrorUnauthorized("unauthorized")))
    }
}

pub fn require_role(
    req: &actix_web::HttpRequest,
    required_role: i32, // эндээс шууд required_role гээд хэрэглэнэ
) -> Result<(), actix_web::Error> {
    if let Some(user) = req.extensions().get::<AuthUser>() {
        if user.role == required_role || user.role == 1 {
            // 1 = admin (doctor_rolls.roll_id)
            return Ok(());
        }
    }
    Err(actix_web::error::ErrorForbidden("forbidden"))
}
