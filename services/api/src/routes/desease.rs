use crate::{
    auth_guard::check_access_and_csrf,
    error::HttpApiError,
    extractors::{AuthUser, require_role},
    schemas::{DiseaseInput, DiseaseUpdate},
    state::AppState,
};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get, post, put,
    web::{self, ReqData},
};
use common::Disease;
use db::{Db, DbError, delete_disease, get_diseases, insert_disease, update_disease};
use serde::Deserialize;

async fn find_disease_by_code_name(db: &Db, code_name: &str) -> Result<Option<Disease>, DbError> {
    let rec = sqlx::query_as::<_, Disease>(
        r#"
        SELECT * FROM public.disease_list
        WHERE code_name = $1
        "#,
    )
    .bind(code_name)
    .fetch_optional(&db.0) // optional → олдохгүй бол None
    .await?;

    Ok(rec)
}

#[post("/disease")]
async fn create(
    req: HttpRequest,
    state: web::Data<AppState>,
    auth_user: AuthUser,
    payload: web::Json<DiseaseInput>,
) -> Result<impl Responder, HttpApiError> {
    check_access_and_csrf(&req)?;

    if let Some(_) = find_disease_by_code_name(&state.db, &payload.code_name).await? {
        return Ok(HttpResponse::BadRequest().body("Тухайн өвчин бүртгэгдсэн байна"));
    }

    let disease = insert_disease(
        &state.db,
        &payload.code_name,
        payload.text_name.as_deref(),
        Some(auth_user.doctor_id), // created_doc_id
        Some(auth_user.org_id),    // created_org_id
        Some(auth_user.doctor_id), // created_doctor_id (FK)
        payload.disease_section.as_deref(),
    )
    .await?;

    Ok(HttpResponse::Ok().json(disease))
}

#[derive(Deserialize)]
pub struct DiseaseQuery {
    pub code_name: Option<String>,
    pub text_name: Option<String>,
}

#[get("/disease")]
async fn list(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<DiseaseQuery>,
) -> Result<impl Responder, HttpApiError> {
    check_access_and_csrf(&req)?;
    require_role(&req, 1)?;

    let diseases = get_diseases(
        &state.db,
        query.code_name.as_deref(),
        query.text_name.as_deref(),
    )
    .await?;

    Ok(HttpResponse::Ok().json(diseases))
}

use actix_web::http::StatusCode;

#[put("/disease/{id}")]
async fn update(
    req: HttpRequest,
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<i32>,
    payload: web::Json<DiseaseUpdate>,
) -> Result<impl Responder, HttpApiError> {
    check_access_and_csrf(&req)?;

    let id = path.into_inner();

    let result = update_disease(
        &state.db,
        id,
        &payload.code_name,
        payload.text_name.as_deref(),
        payload.disease_section.as_deref(),
        auth_user.doctor_id,
        auth_user.org_id,
    )
    .await;

    match result {
        Ok(disease) => Ok(HttpResponse::Ok().json(disease)),
        Err(_) => Ok(
            HttpResponse::build(StatusCode::FORBIDDEN).body("Та энэ өвчнийг засах эрхгүй байна")
        ),
    }
}

#[delete("/disease/{id}")]
async fn remove(
    req: HttpRequest,
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<i32>,
) -> Result<impl Responder, HttpApiError> {
    check_access_and_csrf(&req)?;

    let id = path.into_inner();

    match delete_disease(&state.db, id, auth_user.doctor_id, auth_user.org_id).await {
        Ok(_) => Ok(HttpResponse::Ok().body("Өвчин амжилттай устлаа")),
        Err(DbError::NotFound) => Ok(HttpResponse::NotFound().body("Өвчин олдсонгүй")),
        Err(DbError::Forbidden) => {
            Ok(HttpResponse::Forbidden().body("Та энэ өвчнийг устгах эрхгүй байна"))
        }
        Err(e) => Err(HttpApiError::Db(e)),
    }
}
