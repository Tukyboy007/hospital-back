use crate::error::HttpApiError;
use crate::{
    schemas::{LoginInput, RegisterInput},
    state::AppState,
};
use actix_web::{HttpRequest, HttpResponse, post, web};
use auth::{hash_password, sha256_hex, sign_access, sign_refresh, verify_password};
use chrono::{Duration, Utc};
use db::{
    find_doctor_by_reg_no, get_refresh_by_jti, insert_doctor_user, insert_refresh, revoke_refresh,
};
use serde_json::json;

const ACCESS_COOKIE: &str = "access_token";
const REFRESH_COOKIE: &str = "refresh_token";
const CSRF_COOKIE: &str = "csrf_token";
#[post("/auth/register")]
pub async fn register(
    data: web::Data<AppState>,
    payload: web::Json<RegisterInput>,
) -> actix_web::Result<HttpResponse> {
    let payload = payload.into_inner();
    println!("➡️ REGISTER STARTED with reg_no={}", payload.reg_no);

    // 1️⃣ давхцсан doctor шалгах
    if find_doctor_by_reg_no(&data.db, &payload.reg_no)
        .await
        .map_err(|e| {
            println!("❌ DB FIND ERROR: {:?}", e);
            actix_web::error::ErrorInternalServerError("db error")
        })?
        .is_some()
    {
        println!("⚠️ REG_NO already exists");
        return Err(actix_web::error::ErrorConflict("reg_no already exists"));
    }

    // 2️⃣ password hash үүсгэх
    let hash = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(e) => {
            println!("❌ HASH ERROR: {:?}", e);
            return Err(actix_web::error::ErrorInternalServerError("hash error"));
        }
    };

    // 3️⃣ doctor_user insert
    let doctor = match insert_doctor_user(
        &data.db,
        &payload.reg_no,
        &payload.first_name,
        &payload.last_name,
        payload.rank_name.as_deref(),
        payload.org_name.as_deref(),
        payload.org_id,
        payload.position.as_deref(),
        payload.birth_date,
        payload.gender.as_deref(),
        payload.doctor_roll,
        &hash,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            println!("❌ INSERT ERROR: {:?}", e);
            return Err(actix_web::error::ErrorInternalServerError("insert error"));
        }
    };

    println!("✅ INSERT SUCCESS id={}", doctor.id);

    // 4️⃣ JWT үүсгэх
    let keys = &data.jwt;
    let access = sign_access(keys, doctor.id, "Doctor", data.access_ttl)
        .map_err(|_| actix_web::error::ErrorInternalServerError("sign access"))?;
    let (refresh_token, claims) = sign_refresh(keys, doctor.id, "Doctor", data.refresh_ttl)
        .map_err(|_| actix_web::error::ErrorInternalServerError("sign refresh"))?;

    // 5️⃣ Refresh DB
    let token_hash = format!("sha256:{}", sha256_hex(&refresh_token));
    let expires_at = Utc::now() + chrono::Duration::seconds(data.refresh_ttl);
    if let Err(e) = insert_refresh(&data.db, doctor.id, &claims.jti, &token_hash, expires_at).await
    {
        println!("❌ REFRESH INSERT ERROR: {:?}", e);
        return Err(actix_web::error::ErrorInternalServerError("insert refresh"));
    }

    println!("✅ GISTER DONE for {}", payload.reg_no);

    Ok(HttpResponse::Created().json(json!({
        "doctor": {
            "id": doctor.id,
            "reg_no": doctor.reg_no,
            "first_name": doctor.first_name,
            "last_name": doctor.last_name
        },
        "tokens": {
            "access": access,
            "refresh": refresh_token,
            "jti": claims.jti
        }
    })))
}

/// 🧠 Login doctor
#[post("/auth/login")]
pub async fn login(
    data: web::Data<AppState>,
    payload: web::Json<LoginInput>,
) -> actix_web::Result<HttpResponse> {
    let payload = payload.into_inner();

    // 1️⃣ reg_no-гоор doctor хайх
    let doctor = find_doctor_by_reg_no(&data.db, &payload.reg_no)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("db error"))?;

    let doctor = if let Some(doc) = doctor {
        doc
    } else {
        return Err(actix_web::error::ErrorUnauthorized("invalid credentials"));
    };

    // 2️⃣ password verify хийх
    if !verify_password(&payload.password, &doctor.password_hash) {
        return Err(actix_web::error::ErrorUnauthorized("invalid password"));
    }

    // 3️⃣ JWT үүсгэх
    let keys = &data.jwt;
    let access = sign_access(keys, doctor.id, "Doctor", data.access_ttl)
        .map_err(|_| actix_web::error::ErrorInternalServerError("sign access"))?;
    let (refresh_token, claims) = sign_refresh(keys, doctor.id, "Doctor", data.refresh_ttl)
        .map_err(|_| actix_web::error::ErrorInternalServerError("sign refresh"))?;

    // 4️⃣ Refresh токен DB-д хадгалах
    let token_hash = format!("sha256:{}", sha256_hex(&refresh_token));
    let expires_at = Utc::now() + chrono::Duration::seconds(data.refresh_ttl);
    insert_refresh(&data.db, doctor.id, &claims.jti, &token_hash, expires_at)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("insert refresh"))?;

    // ✅ Response
    Ok(HttpResponse::Ok().json(json!({
        "doctor": {
            "id": doctor.id,
            "reg_no": doctor.reg_no,
            "first_name": doctor.first_name,
            "last_name": doctor.last_name
        },
        "tokens": {
            "access": access,
            "refresh": refresh_token,
            "jti": claims.jti
        }
    })))
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
    let claims = auth::verify(&data.jwt, &token)
        .map_err(|_| actix_web::error::ErrorUnauthorized("bad refresh"))?;

    println!(
        "➡️ REFRESH STARTED for sub={} jti={}",
        claims.sub, claims.jti
    );

    // 🔍 DB check
    if let Some(row) = get_refresh_by_jti(&data.db, &claims.jti)
        .await
        .map_err(HttpApiError::from)?
    {
        if row.revoked {
            println!("❌ REFRESH: token revoked");
            return Err(actix_web::error::ErrorUnauthorized("revoked"));
        }
        let given_hash = format!("sha256:{}", sha256_hex(&token));
        if given_hash != row.token_hash {
            println!("❌ REFRESH: token mismatch");
            return Err(actix_web::error::ErrorUnauthorized("mismatch"));
        }
    } else {
        println!("❌ REFRESH: missing refresh token in DB");
        return Err(actix_web::error::ErrorUnauthorized("missing"));
    }

    println!("✅ REFRESH: passed validation, rotating...");

    revoke_refresh(&data.db, &claims.jti)
        .await
        .map_err(crate::error::HttpApiError::from)?;

    let access = auth::sign_access(&data.jwt, claims.sub, &claims.role, data.access_ttl)
        .map_err(|_| HttpApiError::Auth)?;
    let (refresh_new, claims_new) =
        auth::sign_refresh(&data.jwt, claims.sub, &claims.role, data.refresh_ttl)
            .map_err(|_| HttpApiError::Auth)?;

    println!("✅ REFRESH: generated new access and refresh");

    let token_hash = format!("sha256:{}", sha256_hex(&refresh_new));
    let expires_at = Utc::now() + Duration::seconds(data.refresh_ttl);
    let _ = insert_refresh(
        &data.db,
        claims.sub,
        &claims_new.jti,
        &token_hash,
        expires_at,
    )
    .await
    .map_err(HttpApiError::from)?;

    println!("✅ REFRESH: inserted new refresh record");

    let c = actix_web::cookie::Cookie::build(REFRESH_COOKIE, refresh_new)
        .domain(data.cookie_domain.clone())
        .secure(data.cookie_secure)
        .http_only(true)
        .path("/")
        .finish();

    println!("✅ REFRESH: cookie built successfully");

    let mut resp = HttpResponse::Ok().json(json!({
        "access_token": access
    }));

    resp.add_cookie(&c).ok();
    println!("✅ REFRESH: response ready");
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
