use actix_web::test;
use api::create_app; // 👈 lib.rs доторх create_app-г ашиглана
use api::state::AppState;
use auth::JwtKeys;
use db::connect;
use serde_json::json;
use std::env;
use uuid::Uuid;

#[actix_web::test] // 👈 actix_rt::test биш, actix_web::test хэрэглэнэ
async fn test_auth_flow_register_login_refresh_logout() {
    dotenvy::dotenv().ok();

    // ⚙️ Тест DB холболт
    let db_url = env::var("TEST_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .expect("❌ DATABASE_URL тохируулагдаагүй байна");
    let db = connect(&db_url, 5).await.expect("❌ DB холбогдсонгүй");

    // ⚙️ JWT key
    let keys = JwtKeys::from_secret("test_secret_key");

    // ⚙️ AppState mock
    let state = AppState {
        db,
        jwt: keys,
        access_ttl: 3600,              // 1 цаг
        refresh_ttl: 60 * 60 * 24 * 7, // 7 хоног
        cookie_domain: "localhost".into(),
        cookie_secure: false,
    };

    // ⚙️ App үүсгэх (lib.rs доторхи create_app ашиглана)
    let app = test::init_service(create_app(state.clone())).await;

    // ==========================================
    // ✅ 1. REGISTER TEST
    // ==========================================
    let reg_no = format!("DOC-{}", Uuid::new_v4());
    let register_payload = json!({
        "reg_no": reg_no,
        "first_name": "Temuulen",
        "last_name": "Bat",
        "rank_name": "Surgeon",
        "org_name": "UB Hospital",
        "org_id": 1,
        "position": "Cardio",
        "birth_date": "1990-05-12",
        "gender": "male",
        "doctor_roll": 1,
        "password": "supersecret"
    });

    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&register_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "Register endpoint failed (status: {:?})",
        resp.status()
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    let doctor_id = body["doctor"]["id"].as_str().unwrap().to_string();
    let access_token = body["tokens"]["access"].as_str().unwrap().to_string();
    let refresh_token = body["tokens"]["refresh"].as_str().unwrap().to_string();

    println!("✅ Registered doctor_id={doctor_id}");
    println!("Access token (first 40 chars): {}", &access_token[..40]);
    println!("Refresh token (first 40 chars): {}", &refresh_token[..40]);

    // ==========================================
    // ✅ 2. LOGIN TEST
    // ==========================================
    let login_payload = json!({
        "reg_no": register_payload["reg_no"],
        "password": "supersecret"
    });

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(&login_payload)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "Login endpoint failed");

    let body: serde_json::Value = test::read_body_json(resp).await;
    let new_access = body["tokens"]["access"].as_str().unwrap();
    let new_refresh = body["tokens"]["refresh"].as_str().unwrap();

    assert!(new_access.starts_with("ey"), "Invalid JWT access");
    assert!(new_refresh.starts_with("ey"), "Invalid JWT refresh");
    println!("✅ Login successful");

    // ==========================================
    // ✅ 3. REFRESH TEST
    // ==========================================
    let req = test::TestRequest::post()
        .uri("/auth/refresh")
        .cookie(
            actix_web::cookie::Cookie::build("refresh_token", new_refresh.to_string())
                .path("/")
                .finish(),
        )
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "Refresh endpoint failed (got {:?})",
        resp.status()
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["access_token"].as_str().unwrap().starts_with("ey"),
        "Invalid refreshed access token"
    );
    println!("✅ Refresh token rotated successfully");

    // ==========================================
    // ✅ 4. LOGOUT TEST
    // ==========================================
    let req = test::TestRequest::post()
        .uri("/auth/logout")
        .cookie(
            actix_web::cookie::Cookie::build("refresh_token", new_refresh.to_string())
                .path("/")
                .finish(),
        )
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "Logout endpoint failed (got {:?})",
        resp.status()
    );

    println!("✅ Logout successful");
}
