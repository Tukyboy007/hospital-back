use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterInput {
    #[validate(length(min = 5, message = "reg_no must be at least 5 characters"))]
    pub reg_no: String,

    #[validate(length(min = 2, max = 64, message = "first_name must be 2–64 characters"))]
    pub first_name: String,

    #[validate(length(min = 2, max = 64, message = "last_name must be 2–64 characters"))]
    pub last_name: String,

    #[validate(length(min = 8, max = 128, message = "password must be at least 8 characters"))]
    pub password: String,

    pub rank_name: Option<String>,
    pub org_name: Option<String>,
    pub org_id: i32,
    pub position: Option<String>,
    pub birth_date: Option<NaiveDate>,
    pub gender: Option<String>,
    pub doctor_roll: i32,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginInput {
    #[validate(length(min = 5, message = "reg_no must be at least 5 characters"))]
    pub reg_no: String,
    #[validate(length(min = 6, max = 128, message = "password must be at least 6 characters"))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemIn {
    pub title: String,
    #[serde(alias = "description")]
    pub description: Option<String>,
}
