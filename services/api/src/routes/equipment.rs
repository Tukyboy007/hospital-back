use crate::error::HttpApiError;
use crate::extractors::AuthUser;
use crate::schemas::{EquipmentReportInput, FixedReportInput};
use crate::{auth_guard::check_access_and_csrf, state::AppState};
use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use bigdecimal::BigDecimal;
use chrono::{DateTime, NaiveDate, Utc};
use common::{EquipmentFilter, EquipmentReportFilter, HospitalEquipment};
use db::{
    Db, DbError, fixed_report_create, insert_equipment_report, insert_hospital_equipment,
    list_equipment_reports, list_hospital_equipment,
};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct HospitalEquipmentInput {
    pub fixed_id: Option<i32>,
    pub name: Option<String>,
    pub count: Option<i32>,
    pub created_date: Option<DateTime<Utc>>,
    pub each_price: Option<f64>,
    pub serial_no: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub equipment_type_id: Option<i32>,
    pub is_active: bool,
}

#[post("/equipment")]
async fn create(
    req: HttpRequest,
    state: web::Data<AppState>,
    auth_user: AuthUser,
    payload: web::Json<HospitalEquipmentInput>,
) -> Result<HttpResponse, HttpApiError> {
    check_access_and_csrf(&req)?;

    // f64 -> BigDecimal хөрвүүлэлт
    let each_price = payload
        .each_price
        .map(|p| BigDecimal::from_str(&p.to_string()).unwrap());

    // DB insert → HospitalEquipment буцаана
    let equipment = insert_hospital_equipment(
        &state.db,
        payload.fixed_id,
        payload.name.as_deref(),
        payload.count,
        payload.created_date,
        each_price,
        payload.serial_no.as_deref(),
        payload.purchase_date,
        payload.equipment_type_id,
        Some(auth_user.org_id),
        payload.is_active,         // ✅ 10 дахь нь bool
        Some(auth_user.doctor_id), // ✅ 11 дахь нь created_doc_id
    )
    .await?;

    // Буцаахдаа HospitalEquipment-г JSON болгож дамжуулна
    Ok(HttpResponse::Ok().json(equipment))
}

#[get("/equipment/list")]
async fn list_equipment(
    req: HttpRequest,
    state: web::Data<AppState>,
    auth_user: AuthUser,
    web::Query(filter): web::Query<EquipmentFilter>,
) -> Result<impl Responder, HttpApiError> {
    check_access_and_csrf(&req)?;

    let equipments = list_hospital_equipment(&state.db, filter).await?;
    Ok(HttpResponse::Ok().json(equipments))
}

#[post("/equipment/report")]
async fn create_report(
    req: HttpRequest,
    state: web::Data<AppState>,
    auth_user: AuthUser,
    payload: web::Json<EquipmentReportInput>,
) -> Result<HttpResponse, HttpApiError> {
    check_access_and_csrf(&req)?;

    let report = insert_equipment_report(
        &state.db,
        payload.report_id,
        payload.issue_description.as_deref(),
        payload.reason.as_deref(),
        payload.broken_date,
        payload.fixed_date, // ✅ function дотор fixed_date нэмсэн
        payload.status.as_deref(),
        Some(auth_user.org_id),    // i32 хэвээр үлдэнэ
        Some(auth_user.doctor_id), // ✅ i64 болгосон
    )
    .await?;

    Ok(HttpResponse::Ok().json(report))
}

#[get("/equipment/report/list")]
async fn list_reports(
    req: HttpRequest,
    state: web::Data<AppState>,
    auth_user: AuthUser,
    web::Query(filter): web::Query<EquipmentReportFilter>,
) -> Result<impl Responder, HttpApiError> {
    check_access_and_csrf(&req)?;

    let reports = list_equipment_reports(
        &state.db,
        filter.report_id,
        filter.created_org_id,
        filter.created_doctor_id,
        filter.status.clone(),
        filter.broken_date_from,
        filter.broken_date_to,
        filter.fixed_date_from,
        filter.fixed_date_to,
    )
    .await?;

    Ok(HttpResponse::Ok().json(reports))
}

#[post("/equipment/report/fix")]
async fn fix_report(
    req: HttpRequest,
    state: web::Data<AppState>,
    auth_user: AuthUser,
    payload: web::Json<FixedReportInput>,
) -> Result<HttpResponse, HttpApiError> {
    check_access_and_csrf(&req)?;

    let result = fixed_report_create(
        &state.db,
        payload.report_id,
        Some(&payload.reason),
        payload.fixed_date,
        Some(auth_user.org_id),
        Some(auth_user.doctor_id),
    )
    .await?;

    match result {
        Ok(report) => Ok(HttpResponse::Ok().json(report)),
        Err(msg) => Ok(HttpResponse::Ok().json(msg)), // "Төхөөрөмж хэвийн байна"
    }
}
