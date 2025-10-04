use serde::Deserialize;

#[derive(Deserialize)]
pub struct RegisterInput {
    pub reg_no: String,
    pub first_name: String,
    pub last_name: String,
    pub rank_name: Option<String>,
    pub org_name: Option<String>,
    pub org_id: i32,
    pub position: Option<String>,
    pub birth_date: Option<chrono::NaiveDate>,
    pub gender: Option<String>,
    pub doctor_roll: Option<i32>,
    pub password: String,
}
#[derive(Debug, Deserialize)]
pub struct LoginInput {
    pub reg_no: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemIn {
    pub title: String,
    #[serde(alias = "description")]
    pub description: Option<String>,
}
