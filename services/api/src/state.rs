use auth::JwtKeys;
use db::Db;
use serde::Deserialize;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub jwt: JwtKeys,
    pub access_ttl: i64,
    pub refresh_ttl: i64,
    pub cookie_domain: String,
    pub cookie_secure: bool,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub database_url: String,
    pub jwt_secret: String,
    pub access_ttl_seconds: Option<i64>,
    pub refresh_ttl_seconds: Option<i64>,
    pub cookie_domain: Option<String>,
    pub cookie_secure: Option<bool>,
}

impl Settings {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        let cfg = config::Config::builder()
            .add_source(
                config::Environment::default()
                    // .separator("_")  // <= ҮҮНИЙГ БҮҮ АШИГЛА
                    .try_parsing(true),
            )
            .build()
            .expect("config");

        cfg.try_deserialize::<Settings>()
            .expect("deserialize settings")
    }
}
