use chrono::{DateTime, Utc};
use common::DoctorUserRow;
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Db(pub PgPool);

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

pub async fn connect(database_url: &str, max: u32) -> Result<Db, DbError> {
    let pool = PgPoolOptions::new()
        .max_connections(max)
        .connect(database_url)
        .await?;
    Ok(Db(pool))
}

pub async fn migrate(db: &Db) -> Result<(), DbError> {
    sqlx::migrate!("./migrations").run(&db.0).await?;
    Ok(())
}

// ==== Models mirrored locally for convenience (could use `common`) ====
#[derive(sqlx::FromRow, Debug, Clone, Serialize)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone, Serialize)]
pub struct ItemRow {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn find_doctor_by_reg_no(
    db: &Db,
    reg_no: &str,
) -> Result<Option<DoctorUserRow>, DbError> {
    let row = sqlx::query_as!(
        DoctorUserRow,
        r#"SELECT * FROM doctor_user WHERE reg_no = $1"#,
        reg_no
    )
    .fetch_optional(&db.0)
    .await?;
    Ok(row)
}

pub async fn insert_doctor_user(
    db: &Db,
    reg_no: &str,
    first_name: &str,
    last_name: &str,
    rank_name: Option<&str>,
    org_name: Option<&str>,
    org_id: i32,
    position: Option<&str>,
    birth_date: Option<chrono::NaiveDate>,
    gender: Option<&str>,
    doctor_roll: Option<i32>,
    password_hash: &str,
) -> Result<DoctorUserRow, DbError> {
    let row = sqlx::query_as!(
        DoctorUserRow,
        r#"
        INSERT INTO doctor_user (
            reg_no, first_name, last_name, rank_name, org_name, org_id,
            position, birth_date, gender, doctor_roll, password_hash, is_active
        )
        VALUES (
            $1,$2,$3,$4,$5,$6,
            $7,$8,$9,$10,$11,TRUE
        )
        RETURNING 
            id, doctor_id, rank_name, first_name, last_name, org_name,
            org_id, reg_no, position, birth_date, gender,
            doctor_roll, created_at, updated_at, password_hash, is_active
        "#,
        reg_no,
        first_name,
        last_name,
        rank_name,
        org_name,
        org_id,
        position,
        birth_date,
        gender,
        doctor_roll,
        password_hash
    )
    .fetch_one(&db.0)
    .await?;

    Ok(row)
}

pub async fn insert_user(
    db: &Db,
    email: &str,
    name: &str,
    password_hash: &str,
    role: &str,
) -> Result<UserRow, DbError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"INSERT INTO users (email,name,password_hash,role)
            VALUES ($1,$2,$3,$4)
            RETURNING id,email,password_hash,name,role,created_at"#,
    )
    .bind(email)
    .bind(name)
    .bind(password_hash)
    .bind(role)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
}

// ==== Items ====
pub async fn list_items(db: &Db, owner: Option<Uuid>) -> Result<Vec<ItemRow>, DbError> {
    if let Some(owner_id) = owner {
        let rows = sqlx::query_as::<_, ItemRow>(
            "SELECT * FROM items WHERE owner_id = $1 ORDER BY created_at DESC",
        )
        .bind(owner_id)
        .fetch_all(&db.0)
        .await?;
        Ok(rows)
    } else {
        let rows = sqlx::query_as::<_, ItemRow>("SELECT * FROM items ORDER BY created_at DESC")
            .fetch_all(&db.0)
            .await?;
        Ok(rows)
    }
}

pub async fn get_item(db: &Db, id: Uuid) -> Result<Option<ItemRow>, DbError> {
    let row = sqlx::query_as::<_, ItemRow>("SELECT * FROM items WHERE id=$1")
        .bind(id)
        .fetch_optional(&db.0)
        .await?;
    Ok(row)
}

pub async fn insert_item(
    db: &Db,
    owner_id: Uuid,
    title: &str,
    description: Option<&str>,
) -> Result<ItemRow, DbError> {
    let row = sqlx::query_as::<_, ItemRow>(
        r#"INSERT INTO items (owner_id,title,description)
           VALUES ($1,$2,$3)
           RETURNING id, owner_id, title, description, created_at, updated_at"#,
    )
    .bind(owner_id)
    .bind(title)
    .bind(description)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
}

pub async fn update_item(
    db: &Db,
    id: Uuid,
    title: &str,
    description: Option<&str>,
) -> Result<Option<ItemRow>, DbError> {
    let row = sqlx::query_as::<_, ItemRow>(
        r#"UPDATE items SET title=$2, description=$3, updated_at=NOW()
           WHERE id=$1
           RETURNING id, owner_id, title, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(title)
    .bind(description)
    .fetch_optional(&db.0)
    .await?;
    Ok(row)
}

pub async fn delete_item(db: &Db, id: Uuid) -> Result<u64, DbError> {
    let res = sqlx::query("DELETE FROM items WHERE id=$1")
        .bind(id)
        .execute(&db.0)
        .await?;
    Ok(res.rows_affected())
}

// ==== Refresh tokens (rotation) ====

#[derive(sqlx::FromRow, Debug, Serialize, Clone)]
pub struct RefreshRow {
    pub id: i64,
    pub doctor_id: Uuid,
    pub jti: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_refresh(
    db: &Db,
    doctor_id: Uuid,
    jti: &str,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), DbError> {
    println!("➡️ INSERT REFRESH doctor_id={doctor_id}, jti={jti}, expires_at={expires_at}");
    let result = sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (doctor_id, jti, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
        doctor_id,
        jti,
        token_hash,
        expires_at
    )
    .execute(&db.0)
    .await;

    match result {
        Ok(_) => {
            println!("✅ REFRESH INSERT OK");
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ REFRESH INSERT ERROR: {:?}", e);
            Err(DbError::from(e))
        }
    }
}

pub async fn get_refresh_by_jti(db: &Db, jti: &str) -> Result<Option<RefreshRow>, DbError> {
    let row = sqlx::query_as::<_, RefreshRow>("SELECT * FROM refresh_tokens WHERE jti=$1")
        .bind(jti)
        .fetch_optional(&db.0)
        .await?;
    Ok(row)
}

pub async fn revoke_refresh(db: &Db, jti: &str) -> Result<u64, DbError> {
    let res = sqlx::query("UPDATE refresh_tokens SET revoked=true WHERE jti=$1")
        .bind(jti)
        .execute(&db.0)
        .await?;
    Ok(res.rows_affected())
}
