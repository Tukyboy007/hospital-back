use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
}

impl Default for Role {
    fn default() -> Self {
        Role::User
    }
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct DoctorUserRow {
    pub id: Uuid,
    pub reg_no: String,                // NOT NULL
    pub first_name: Option<String>,    // NULL байж болно
    pub last_name: Option<String>,     // NULL байж болно
    pub rank_name: Option<String>,     // NULL байж болно
    pub org_name: Option<String>,      // NULL байж болно
    pub org_id: Option<Uuid>,          // NULL байж болно
    pub position: Option<String>,      // NULL байж болно
    pub birth_date: Option<NaiveDate>, // NULL байж болно
    pub gender: Option<String>,        // NULL байж болно
    pub password_hash: String,         // NOT NULL
    pub doctor_roll: Option<i32>,      // FK, NULL байж болно
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error")]
    Internal,
}

pub type AppResult<T> = Result<T, AppError>;
