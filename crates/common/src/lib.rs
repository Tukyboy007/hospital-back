use chrono::{DateTime, Utc};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub name: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
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

#[derive(sqlx::FromRow, Debug, Clone, serde::Serialize)]
pub struct DoctorUserRow {
    pub id: uuid::Uuid,
    pub doctor_id: i64,
    pub rank_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub org_name: Option<String>,
    pub org_id: i32,
    pub reg_no: String,
    pub position: Option<String>,
    pub birth_date: Option<chrono::NaiveDate>,
    pub gender: Option<String>,
    pub doctor_roll: Option<i32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub password_hash: String,
    pub is_active: bool,
}
