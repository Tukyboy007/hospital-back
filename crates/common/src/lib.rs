use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;
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
    pub doctor_id: i64,                // NOT NULL
    pub reg_no: String,                // NOT NULL
    pub first_name: Option<String>,    // NULL байж болно
    pub last_name: Option<String>,     // NULL байж болно
    pub rank_name: Option<String>,     // NULL байж болно
    pub org_name: Option<String>,      // NULL байж болно
    pub org_id: i32,                   // NOT NULL
    pub position: Option<String>,      // NULL байж болно
    pub birth_date: Option<NaiveDate>, // NULL байж болно
    pub gender: Option<String>,        // NULL байж болно
    pub password_hash: String,         // NOT NULL
    pub doctor_roll: i32,              // FK, NULL байж болно
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct Disease {
    pub id: i32,
    pub code_name: String,
    pub text_name: Option<String>,
    pub created_doc_id: Option<i32>,
    pub created_org_id: Option<i32>,
    pub created_doctor_id: Option<i64>,
    pub disease_section: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct EquipmentReport {
    pub id: i64,
    pub report_id: i64, // FK hospital_equipment.report_id
    pub issue_description: Option<String>,
    pub reason: Option<String>,
    pub broken_date: Option<NaiveDate>,
    pub fixed_date: Option<NaiveDate>,
    pub status: Option<String>,
    pub created_org_id: Option<i32>,
    pub created_doctor_id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct HospitalEquipment {
    pub id: i64,
    pub fixed_id: Option<i32>,
    pub name: Option<String>,
    pub count: Option<i32>,
    pub created_date: Option<DateTime<Utc>>,
    pub each_price: Option<BigDecimal>,
    pub serial_no: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub equipment_type_id: Option<i32>,
    pub org_id: Option<i32>,
    pub report_id: Option<i64>, // ✅ BIGINT тул i64
    pub is_active: bool,
    pub created_doc_id: Option<i64>, // ✅ BIGINT тул i64
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct EquipmentFilter {
    pub name: Option<String>,
    pub created_date_from: Option<DateTime<Utc>>,
    pub created_date_to: Option<DateTime<Utc>>,
    pub created_doc_id: Option<i64>,
    pub is_active: Option<bool>,
    pub org_id: Option<i32>,
    pub equipment_type_id: Option<i32>,
    pub serial_no: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EquipmentReportFilter {
    pub report_id: Option<i64>,
    pub created_org_id: Option<Vec<i32>>,
    pub created_doctor_id: Option<i64>,
    pub status: Option<String>,
    pub broken_date_from: Option<NaiveDate>,
    pub broken_date_to: Option<NaiveDate>,
    pub fixed_date_from: Option<NaiveDate>,
    pub fixed_date_to: Option<NaiveDate>,
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
