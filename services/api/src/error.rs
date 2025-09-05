use actix_web::{HttpResponse, ResponseError};
use common::AppError;
use db::DbError;
use std::fmt;
use thiserror::Error;
#[derive(Debug, thiserror::Error)]
pub enum HttpApiError {
    #[error("{0}")]
    App(#[from] AppError),

    #[error("{0}")]
    Db(#[from] DbError),

    #[error("auth error")]
    Auth,
}

impl actix_web::ResponseError for HttpApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            HttpApiError::Db(DbError::Constraint(msg)) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "constraint_violation",
                    "message": msg
                }))
            }
            HttpApiError::Db(DbError::NotFound) => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "not_found",
                    "message": "Record not found"
                }))
            }
            HttpApiError::Db(DbError::Forbidden) => {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "forbidden",
                    "message": "You do not have permission"
                }))
            }
            other => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "internal_error",
                "message": other.to_string()
            })),
        }
    }
}
