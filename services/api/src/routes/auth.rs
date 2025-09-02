use crate::error::HttpApiError;
use actix_web::{HttpRequest, HttpResponse, post, web};
use auth::{hash_password, sha256_hex, verify_password};
use chrono::{Duration, Utc};
use db::{
    find_doctor_by_reg_no, get_refresh_by_jti, insert_doctor_user, insert_refresh, revoke_refresh,
};
use serde_json::json;
use validator::Validate;

use crate::{
    schemas::{LoginInput, RegisterInput, TokenPair},
    state::AppState,
};

const ACCESS_COOKIE: &str = "access_token";
const REFRESH_COOKIE: &str = "refresh_token";
const CSRF_COOKIE: &str = "csrf_token";

#[post("/auth/register")]
pub async fn register(
    data: web::Data<AppState>,
    payload: web::Json<RegisterInput>,
) -> actix_web::Result<HttpResponse> {
    // validate input
    payload
        .validate()
        .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

    // check duplicate reg_no
    if find_doctor_by_reg_no(&data.db, &payload.reg_no)
        .await
        .map_err(HttpApiError::from)?
        .is_some()
    {
        return Err(actix_web::error::ErrorConflict("reg_no already exists"));
    }

    // hash password
    let hash = hash_password(&payload.password)
        .map_err(|_| actix_web::error::ErrorInternalServerError("hash error"))?;

    // insert new doctor user
    let user = insert_doctor_user(
        &data.db,
        &payload.reg_no,
        &payload.first_name,
        &payload.last_name,
        &hash,
        payload.rank_name.as_deref(),
        payload.org_name.as_deref(),
        payload.org_id,
        payload.position.as_deref(),
        payload.birth_date,
        payload.gender.as_deref(),
        payload.doctor_roll,
    )
    .await
    .map_err(HttpApiError::from)?;

    let access = auth::sign_access(
        &data.jwt,
        user.id,
        user.doctor_id,
        &user.reg_no,
        user.doctor_roll,
        user.org_id,
        data.access_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("JWT generation failed"))?;

    let (refresh_token, claims) = auth::sign_refresh(
        &data.jwt,
        user.id,
        user.doctor_id,
        user.doctor_roll,
        &user.reg_no,
        user.org_id,
        data.refresh_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("Refresh token generation failed"))?;

    // DB-д refresh token хадгалах
    let token_hash = format!("sha256:{}", auth::sha256_hex(&refresh_token));
    let expires_at = Utc::now() + chrono::Duration::seconds(data.refresh_ttl);
    let _ = db::insert_refresh(&data.db, user.id, &claims.jti, &token_hash, expires_at)
        .await
        .map_err(HttpApiError::from)?;

    // cookie common settings
    let cookie_common = actix_web::cookie::CookieBuilder::new("dummy", "dummy")
        // .domain(data.cookie_domain.clone()) // түр унтраасан бол буцаагаад тохируулах боломжтой
        .http_only(true)
        .secure(data.cookie_secure)
        .path("/")
        .finish();

    // access token cookie
    let mut access_cookie = cookie_common.clone();
    access_cookie.set_name(ACCESS_COOKIE);
    access_cookie.set_value(access.clone());
    access_cookie.set_http_only(true);

    // refresh token cookie
    let mut refresh_cookie = cookie_common.clone();
    refresh_cookie.set_name(REFRESH_COOKIE);
    refresh_cookie.set_value(refresh_token);

    // csrf token cookie
    let csrf_token = auth::new_jti();
    let mut csrf_cookie = cookie_common.clone();
    csrf_cookie.set_name(CSRF_COOKIE);
    csrf_cookie.set_value(csrf_token.clone());
    csrf_cookie.set_http_only(false);

    // build response
    let mut resp = HttpResponse::Created().json(json!({
        "id": user.id.to_string(),
        "doctor_id": user.doctor_id,
        "reg_no": user.reg_no,
        "first_name": user.first_name.unwrap_or_default(),
        "last_name": user.last_name.unwrap_or_default(),
        "doctor_roll": user.doctor_roll,
        "org_id": user.org_id,
        "access_token": access
    }));
    resp.add_cookie(&access_cookie).ok();
    resp.add_cookie(&refresh_cookie).ok();
    resp.add_cookie(&csrf_cookie).ok();

    Ok(resp)
}

#[post("/auth/login")]
pub async fn login(
    data: web::Data<AppState>,
    payload: web::Json<LoginInput>,
) -> actix_web::Result<HttpResponse> {
    // Input validate
    payload
        .validate()
        .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

    // DB-с reg_no-р хэрэглэгчийг хайх
    let db_user = find_doctor_by_reg_no(&data.db, &payload.reg_no)
        .await
        .map_err(HttpApiError::from)?
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid reg_no or password"))?;

    // Password шалгах
    if !verify_password(&payload.password, &db_user.password_hash) {
        return Err(actix_web::error::ErrorUnauthorized(
            "Invalid reg_no or password",
        ));
    }

    // JWT-д орох role → doctor_roll (int) эсвэл rank_name (string)
    // Хэрэв int-г JWT-д хадгалах гэж байгаа бол doctor_roll-г хэрэглэнэ
    let role = db_user.doctor_roll;

    // Access token гаргах
    let access = auth::sign_access(
        &data.jwt,
        db_user.id,
        db_user.doctor_id,
        &db_user.reg_no,
        role,
        db_user.org_id,
        data.access_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("JWT generation failed"))?;

    // Refresh token гаргах
    let (refresh_token, claims) = auth::sign_refresh(
        &data.jwt,
        db_user.id,
        db_user.doctor_id,
        db_user.doctor_roll,
        &db_user.reg_no,
        db_user.org_id,
        data.refresh_ttl,
    )
    .map_err(|_| actix_web::error::ErrorInternalServerError("Refresh token generation failed"))?;

    // refresh_token-г hash хийж DB-д хадгалах
    let token_hash = format!("sha256:{}", auth::sha256_hex(&refresh_token));
    let expires_at = Utc::now() + chrono::Duration::seconds(data.refresh_ttl);
    let _ = db::insert_refresh(&data.db, db_user.id, &claims.jti, &token_hash, expires_at)
        .await
        .map_err(HttpApiError::from)?;

    // cookie common settings
    let cookie_common = actix_web::cookie::CookieBuilder::new("dummy", "dummy")
        .domain(data.cookie_domain.clone())
        .http_only(true)
        .secure(data.cookie_secure)
        .path("/")
        .finish();

    // access token cookie
    let mut access_cookie = cookie_common.clone();
    access_cookie.set_name(ACCESS_COOKIE);
    access_cookie.set_value(access.clone());
    access_cookie.set_http_only(true);

    // refresh token cookie
    let mut refresh_cookie = cookie_common.clone();
    refresh_cookie.set_name(REFRESH_COOKIE);
    refresh_cookie.set_value(refresh_token);

    // csrf token cookie
    let csrf_token = auth::new_jti();
    let mut csrf_cookie = cookie_common.clone();
    csrf_cookie.set_name(CSRF_COOKIE);
    csrf_cookie.set_value(csrf_token.clone());
    csrf_cookie.set_http_only(false);

    // response
    let mut resp = HttpResponse::Ok().json(TokenPair {
        access_token: access,
    });
    resp.add_cookie(&access_cookie).ok();
    resp.add_cookie(&refresh_cookie).ok();
    resp.add_cookie(&csrf_cookie).ok();

    Ok(resp)
}
#[post("/auth/refresh")]
pub async fn refresh(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let refresh_cookie = req
        .cookie(REFRESH_COOKIE)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("no refresh"))?;
    let token = refresh_cookie.value().to_string();

    // refresh token-оо verify хийнэ
    let claims = auth::verify(&data.jwt, &token)
        .map_err(|_| actix_web::error::ErrorUnauthorized("bad refresh"))?;

    // DB дээр refresh_token байгаа эсэхийг шалгах
    if let Some(row) = get_refresh_by_jti(&data.db, &claims.jti)
        .await
        .map_err(HttpApiError::from)?
    {
        if row.revoked {
            return Err(actix_web::error::ErrorUnauthorized("revoked"));
        }
        let given_hash = format!("sha256:{}", auth::sha256_hex(&token));
        if given_hash != row.token_hash {
            return Err(actix_web::error::ErrorUnauthorized("mismatch"));
        }
    } else {
        return Err(actix_web::error::ErrorUnauthorized("missing"));
    }

    // хэрэглэгчийн мэдээллийг DB-с авна (id-г claims.sub-оос)
    let db_user = db::find_doctor_by_id(&data.db, claims.sub)
        .await
        .map_err(HttpApiError::from)?
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("user not found"))?;

    // шинэ access token үүсгэх
    let access = auth::sign_access(
        &data.jwt,
        db_user.id,
        db_user.doctor_id,
        &db_user.reg_no,
        db_user.doctor_roll,
        db_user.org_id,
        data.access_ttl,
    )
    .map_err(|_| HttpApiError::Auth)?;

    // refresh token-г шинэчлэх
    revoke_refresh(&data.db, &claims.jti)
        .await
        .map_err(HttpApiError::from)?;
    let (refresh_new, claims_new) = auth::sign_refresh(
        &data.jwt,
        db_user.id,
        db_user.doctor_id,
        db_user.doctor_roll,
        &db_user.reg_no,
        db_user.org_id,
        data.refresh_ttl,
    )
    .map_err(|_| HttpApiError::Auth)?;

    let token_hash = format!("sha256:{}", auth::sha256_hex(&refresh_new));
    let expires_at = Utc::now() + Duration::seconds(data.refresh_ttl);
    let _ = insert_refresh(
        &data.db,
        db_user.id,
        &claims_new.jti,
        &token_hash,
        expires_at,
    )
    .await
    .map_err(HttpApiError::from)?;

    // cookie common settings
    let cookie_common = actix_web::cookie::CookieBuilder::new("dummy", "dummy")
        // .domain(data.cookie_domain.clone())
        .http_only(true)
        .secure(data.cookie_secure)
        .path("/")
        .finish();

    // access token cookie
    let mut access_cookie = cookie_common.clone();
    access_cookie.set_name(ACCESS_COOKIE);
    access_cookie.set_value(access.clone());
    access_cookie.set_http_only(true);

    // refresh token cookie
    let mut refresh_cookie = cookie_common.clone();
    refresh_cookie.set_name(REFRESH_COOKIE);
    refresh_cookie.set_value(refresh_new.clone());

    // csrf token cookie
    let csrf_token = auth::new_jti();
    let mut csrf_cookie = cookie_common.clone();
    csrf_cookie.set_name(CSRF_COOKIE);
    csrf_cookie.set_value(csrf_token.clone());
    csrf_cookie.set_http_only(false);

    // response JSON-д бүгдийг буцаая
    let mut resp = HttpResponse::Ok().json(json!({
        "id": db_user.id.to_string(),
        "doctor_id": db_user.doctor_id,
        "reg_no": db_user.reg_no,
        "first_name": db_user.first_name.unwrap_or_default(),
        "last_name": db_user.last_name.unwrap_or_default(),
        "doctor_roll": db_user.doctor_roll,
        "org_id": db_user.org_id,
        "access_token": access,
    }));
    resp.add_cookie(&access_cookie).ok();
    resp.add_cookie(&refresh_cookie).ok();
    resp.add_cookie(&csrf_cookie).ok();

    Ok(resp)
}

#[post("/auth/logout")]
pub async fn logout(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    if let Some(c) = req.cookie(REFRESH_COOKIE) {
        if let Ok(claims) = auth::verify(&data.jwt, c.value()) {
            let _ = revoke_refresh(&data.db, &claims.jti)
                .await
                .map_err(HttpApiError::from)?;
        }
    }
    let clear = |name: &'static str| {
        actix_web::cookie::Cookie::build(name, "")
            .path("/")
            .domain(data.cookie_domain.clone())
            .secure(data.cookie_secure)
            .http_only(true)
            .max_age(actix_web::cookie::time::Duration::seconds(0))
            .finish()
    };
    let mut resp = HttpResponse::Ok().finish();
    resp.add_cookie(&clear(ACCESS_COOKIE)).ok();
    resp.add_cookie(&clear(REFRESH_COOKIE)).ok();
    resp.add_cookie(
        &actix_web::cookie::Cookie::build(CSRF_COOKIE, "")
            .path("/")
            .max_age(actix_web::cookie::time::Duration::seconds(0))
            .finish(),
    )
    .ok();
    Ok(resp)
}
