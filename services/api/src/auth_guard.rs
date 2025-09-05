use actix_web::{HttpRequest, HttpResponse};

use crate::error::HttpApiError;

pub fn check_access_and_csrf(req: &HttpRequest) -> Result<(), HttpApiError> {
    let cookie_access = req.cookie("access_token").map(|c| c.value().to_string());
    if cookie_access.is_none() {
        return Err(HttpApiError::Auth);
    }

    let header_access = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    if header_access.is_none() {
        return Err(HttpApiError::Auth);
    }

    if cookie_access != header_access {
        return Err(HttpApiError::Auth);
    }

    let header_csrf = req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok());
    let cookie_csrf = req.cookie("csrf_token").map(|c| c.value().to_string());

    if header_csrf.is_none() || cookie_csrf.is_none() || header_csrf != cookie_csrf.as_deref() {
        return Err(HttpApiError::Auth);
    }

    Ok(())
}
