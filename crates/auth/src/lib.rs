use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::password_hash::{Error as PasswordHashError, SaltString};
use base64::Engine;
use chrono::Utc;
use jsonwebtoken;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct JwtKeys {
    pub enc: EncodingKey,
    pub dec: DecodingKey,
}

impl JwtKeys {
    pub fn from_secret(secret: &str) -> Self {
        Self {
            enc: EncodingKey::from_secret(secret.as_bytes()),
            dec: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    pub fn encode_access(&self, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
        let token = jsonwebtoken::encode(&Header::default(), claims, &self.enc)?;
        Ok(token)
    }

    pub fn encode_refresh(&self, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = Header::default();
        header.kid = Some(claims.jti.clone());
        let token = jsonwebtoken::encode(&header, claims, &self.enc)?;
        Ok(token)
    }

    pub fn decode(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let data =
            jsonwebtoken::decode::<Claims>(token, &self.dec, &jsonwebtoken::Validation::default())?;
        Ok(data.claims)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,           // doctor_user.id (UUID)
    pub doctor_id: i64,      // BIGSERIAL doctor_id
    pub reg_no: String,      // эмчийн бүртгэлийн дугаар
    pub role: i32,           // doctor_roll (int), Option<i32>
    pub created_org_id: i32, // байгууллагын ID
    pub iat: i64,            // issued at
    pub exp: i64,            // expiry
    pub jti: String,         // unique token id
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,
}

pub fn now_ts() -> i64 {
    Utc::now().timestamp()
}

pub fn new_jti() -> String {
    let mut bytes = [0u8; 16];
    thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
pub fn sign_access(
    keys: &JwtKeys,
    user_id: Uuid,
    doctor_id: i64,
    reg_no: &str,
    role: i32,
    created_org_id: i32,
    ttl: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = now_ts();
    let claims = Claims {
        sub: user_id,
        doctor_id,
        reg_no: reg_no.to_string(),
        role,
        created_org_id,
        iat: now,
        exp: now + ttl,
        jti: new_jti(),
    };

    // энд `keys.enc` ашиглана (access биш!)
    jsonwebtoken::encode(&Header::default(), &claims, &keys.enc)
}

pub fn sign_refresh(
    keys: &JwtKeys,
    user_id: Uuid,
    doctor_id: i64,
    created_org_id: i32,
    reg_no: &str,
    role: i32,
    ttl: i64,
) -> Result<(String, Claims), jsonwebtoken::errors::Error> {
    let now = now_ts();
    let claims = Claims {
        sub: user_id,
        doctor_id,
        reg_no: reg_no.to_string(),
        role,
        created_org_id, // refresh дээр org_id хадгалахгүй
        iat: now,
        exp: now + ttl,
        jti: new_jti(),
    };

    let mut header = Header::default();
    header.kid = Some(claims.jti.clone());

    let token = jsonwebtoken::encode(&header, &claims, &keys.enc)?;
    Ok((token, claims))
}

pub fn verify(keys: &JwtKeys, token: &str) -> Result<Claims, AuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    jsonwebtoken::decode::<Claims>(token, &keys.dec, &validation)
        .map(|d| d.claims)
        .map_err(|_| AuthError::InvalidToken)
}

pub fn hash_password(raw: &str) -> Result<String, PasswordHashError> {
    let salt = SaltString::generate(&mut thread_rng());
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(raw.as_bytes(), &salt)?.to_string();
    Ok(hash)
}

pub fn verify_password(raw: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    if let Ok(parsed) = PasswordHash::new(hash) {
        Argon2::default()
            .verify_password(raw.as_bytes(), &parsed)
            .is_ok()
    } else {
        false
    }
}

pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}
