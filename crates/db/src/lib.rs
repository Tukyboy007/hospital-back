use auth::hash_password;
use bigdecimal::BigDecimal;
use chrono::{DateTime, NaiveDate, Utc};
use common::{Disease, DoctorUserRow, EquipmentFilter, EquipmentReport, HospitalEquipment};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, QueryBuilder, postgres::PgPoolOptions, postgres::Postgres};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Db(pub PgPool);

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("Устгах эрхгүй эсвэл байхгүй байна ")]
    NotFound,

    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("forbidden")]
    Forbidden,
    #[error("password hash error: {0}")]
    PasswordHash(String),

    #[error("db constraint violation: {0}")]
    Constraint(String),
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

#[derive(sqlx::FromRow, Debug, Clone, Serialize)]
pub struct ItemRow {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn insert_doctor_user(
    db: &Db,
    reg_no: &str,
    first_name: &str,
    last_name: &str,
    password_hash: &str,
    rank_name: Option<&str>,
    org_name: Option<&str>,
    org_id: i32, // int, NOT NULL
    position: Option<&str>,
    birth_date: Option<NaiveDate>,
    gender: Option<&str>,
    doctor_roll: i32, // int, NOT NULL
) -> Result<DoctorUserRow, DbError> {
    let row = sqlx::query_as!(
        DoctorUserRow,
        r#"
        INSERT INTO doctor_user (
            reg_no, first_name, last_name, password_hash,
            rank_name, org_name, org_id, position, birth_date, gender, doctor_roll
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING 
            id,
            doctor_id,
            reg_no,
            first_name,
            last_name,
            rank_name,
            org_name,
            org_id,
            position,
            birth_date,
            gender,
            password_hash,
            doctor_roll,
            created_at,
            updated_at,
            is_active
        "#,
        reg_no,
        first_name,
        last_name,
        password_hash,
        rank_name,
        org_name,
        org_id, // ⚡ одоо int
        position,
        birth_date,
        gender,
        doctor_roll // ⚡ одоо int
    )
    .fetch_one(&db.0)
    .await?;

    Ok(row)
}

pub async fn find_doctor_by_reg_no(
    db: &Db,
    reg_no: &str,
) -> Result<Option<DoctorUserRow>, DbError> {
    let row = sqlx::query_as!(
        DoctorUserRow,
        r#"
        SELECT
        id,
        doctor_id,
            reg_no,
            first_name,
            last_name,
            password_hash,
            rank_name,
            org_name,
            org_id,
            position,
            birth_date,
            gender,
            doctor_roll,
            created_at,
            updated_at,
            is_active
        FROM doctor_user
        WHERE reg_no = $1
        "#,
        reg_no
    )
    .fetch_optional(&db.0)
    .await?;

    Ok(row)
}

pub async fn find_doctor_by_id(db: &Db, id: Uuid) -> Result<Option<DoctorUserRow>, DbError> {
    let row = sqlx::query_as!(
        DoctorUserRow,
        r#"
        SELECT
            id,
            doctor_id,
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
            password_hash,
            created_at,
            updated_at,
            is_active
        FROM doctor_user
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&db.0)
    .await?;

    Ok(row)
}

pub async fn reset_doctor_password(db: &Db, reg_no: &str) -> Result<(), DbError> {
    let password_hash =
        hash_password("123456789").map_err(|e| DbError::PasswordHash(e.to_string()))?;

    let rows_affected = sqlx::query(
        r#"
        UPDATE public.doctor_user
        SET password_hash = $1,
            updated_at = NOW()
        WHERE reg_no = $2
        "#,
    )
    .bind(password_hash)
    .bind(reg_no)
    .execute(&db.0)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Err(DbError::NotFound);
    }

    Ok(())
}

pub async fn get_doctor_users(
    db: &Db,
    reg_no: Option<&str>,
    org_id: Option<i32>,
) -> Result<Vec<DoctorUserRow>, DbError> {
    let rows = match (reg_no, org_id) {
        (Some(reg), Some(org)) => {
            sqlx::query_as!(
                DoctorUserRow,
                r#"
                SELECT id, doctor_id, reg_no, first_name, last_name, rank_name,
                       org_name, org_id, position, birth_date, gender,
                       password_hash, doctor_roll, created_at, updated_at, is_active
                FROM doctor_user
                WHERE reg_no = $1 AND org_id = $2
                ORDER BY created_at DESC
                "#,
                reg,
                org
            )
            .fetch_all(&db.0)
            .await?
        }
        (Some(reg), None) => {
            sqlx::query_as!(
                DoctorUserRow,
                r#"
                SELECT id, doctor_id, reg_no, first_name, last_name, rank_name,
                       org_name, org_id, position, birth_date, gender,
                       password_hash, doctor_roll, created_at, updated_at, is_active
                FROM doctor_user
                WHERE reg_no = $1
                ORDER BY created_at DESC
                "#,
                reg
            )
            .fetch_all(&db.0)
            .await?
        }
        (None, Some(org)) => {
            sqlx::query_as!(
                DoctorUserRow,
                r#"
                SELECT id, doctor_id, reg_no, first_name, last_name, rank_name,
                       org_name, org_id, position, birth_date, gender,
                       password_hash, doctor_roll, created_at, updated_at, is_active
                FROM doctor_user
                WHERE org_id = $1
                ORDER BY created_at DESC
                "#,
                org
            )
            .fetch_all(&db.0)
            .await?
        }
        (None, None) => {
            sqlx::query_as!(
                DoctorUserRow,
                r#"
                SELECT id, doctor_id, reg_no, first_name, last_name, rank_name,
                       org_name, org_id, position, birth_date, gender,
                       password_hash, doctor_roll, created_at, updated_at, is_active
                FROM doctor_user
                ORDER BY created_at DESC
                "#
            )
            .fetch_all(&db.0)
            .await?
        }
    };

    Ok(rows)
}

// ==== Disease ====
pub async fn insert_disease(
    db: &Db,
    code_name: &str,
    text_name: Option<&str>,
    created_doc_id: Option<i64>,
    created_org_id: Option<i32>,
    created_doctor_id: Option<i64>,
    disease_section: Option<&str>,
) -> Result<Disease, DbError> {
    let rec = sqlx::query_as::<_, Disease>(
        r#"
        INSERT INTO public.disease_list
            (code_name, text_name, created_doc_id, created_org_id, created_doctor_id, disease_section)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#
    )
    .bind(code_name)
    .bind(text_name)
    .bind(created_doc_id)
    .bind(created_org_id)
    .bind(created_doctor_id)
    .bind(disease_section)
    .fetch_one(&db.0)
    .await?;

    Ok(rec)
}

pub async fn get_diseases(
    db: &Db,
    code_name: Option<&str>,
    text_name: Option<&str>,
) -> Result<Vec<Disease>, DbError> {
    let mut query = String::from("SELECT * FROM public.disease_list WHERE 1=1");

    if code_name.is_some() {
        query.push_str(" AND code_name ILIKE $1");
    }
    if text_name.is_some() {
        query.push_str(" AND text_name ILIKE $2");
    }

    // параметруудыг bind хийхдээ уян хатан болгохын тулд match ашиглая
    let rows = match (code_name, text_name) {
        (Some(code), Some(text)) => {
            sqlx::query_as::<_, Disease>(&query)
                .bind(code)
                .bind(text)
                .fetch_all(&db.0)
                .await?
        }
        (Some(code), None) => {
            sqlx::query_as::<_, Disease>(&query)
                .bind(code)
                .fetch_all(&db.0)
                .await?
        }
        (None, Some(text)) => {
            sqlx::query_as::<_, Disease>(&query)
                .bind(text)
                .fetch_all(&db.0)
                .await?
        }
        (None, None) => {
            sqlx::query_as::<_, Disease>("SELECT * FROM public.disease_list ORDER BY id DESC")
                .fetch_all(&db.0)
                .await?
        }
    };

    Ok(rows)
}

pub async fn update_disease(
    db: &Db,
    id: i32,
    code_name: &str,
    text_name: Option<&str>,
    disease_section: Option<&str>,
    doctor_id: i64,
    org_id: i32,
) -> Result<Disease, DbError> {
    let rec = sqlx::query_as::<_, Disease>(
        r#"
        UPDATE public.disease_list
        SET 
            code_name = $1,
            text_name = $2,
            disease_section = $3
        WHERE id = $4
          AND created_doctor_id = $5
          AND created_org_id = $6
        RETURNING *
        "#,
    )
    .bind(code_name)
    .bind(text_name)
    .bind(disease_section)
    .bind(id)
    .bind(doctor_id)
    .bind(org_id)
    .fetch_one(&db.0)
    .await?;

    Ok(rec)
}

pub async fn delete_disease(db: &Db, id: i32, doctor_id: i64, org_id: i32) -> Result<(), DbError> {
    let rows_affected = sqlx::query(
        r#"
        DELETE FROM public.disease_list
        WHERE id = $1
          AND created_doctor_id = $2
          AND created_org_id = $3
        "#,
    )
    .bind(id)
    .bind(doctor_id)
    .bind(org_id)
    .execute(&db.0)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        // Өөрийнх биш эсвэл байхгүй ID
        return Err(DbError::NotFound);
    }

    Ok(())
}

pub async fn insert_equipment_report(
    db: &Db,
    report_id: i64,
    issue_description: Option<&str>,
    reason: Option<&str>,
    broken_date: Option<NaiveDate>,
    fixed_date: Option<NaiveDate>, // ← нэмэх
    status: Option<&str>,
    created_org_id: Option<i32>,
    created_doctor_id: Option<i64>, // ← i64 болгож өөрчлөх
) -> Result<EquipmentReport, DbError> {
    let rec = sqlx::query_as!(
        EquipmentReport,
        r#"
        INSERT INTO public.equipment_reports
            (report_id, issue_description, reason, broken_date, fixed_date, status, created_org_id, created_doctor_id)
        VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)
        RETURNING 
            id, report_id, issue_description, reason, broken_date, fixed_date, status,
            created_org_id, created_doctor_id, created_at, updated_at
        "#,
        report_id,
        issue_description,
        reason,
        broken_date,
        status,
        created_org_id,
        created_doctor_id
    )
    .fetch_one(&db.0)
    .await?;

    sqlx::query!(
        r#"
        UPDATE public.hospital_equipment
        SET is_active = false, updated_at = NOW()
        WHERE report_id = $1
        "#,
        report_id
    )
    .execute(&db.0)
    .await?;

    Ok(rec)
}

pub async fn insert_hospital_equipment(
    db: &Db,
    fixed_id: Option<i32>,
    name: Option<&str>,
    count: Option<i32>,
    created_date: Option<DateTime<Utc>>,
    each_price: Option<BigDecimal>,
    serial_no: Option<&str>,
    purchase_date: Option<NaiveDate>,
    equipment_type_id: Option<i32>,
    org_id: Option<i32>,
    is_active: bool,
    created_doc_id: Option<i64>,
) -> Result<HospitalEquipment, DbError> {
    let rec = sqlx::query_as!(
        HospitalEquipment,
        r#"
    INSERT INTO public.hospital_equipment
        (fixed_id, name, count, created_date, each_price, serial_no, purchase_date,
         equipment_type_id, org_id, is_active, created_doc_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    RETURNING 
        id, fixed_id, name, count, created_date, each_price, serial_no, purchase_date,
        equipment_type_id, org_id, report_id, is_active, created_doc_id,
        created_at, updated_at
    "#,
        fixed_id,
        name,
        count,
        created_date,
        each_price,
        serial_no,
        purchase_date,
        equipment_type_id,
        org_id,
        is_active,
        created_doc_id
    )
    .fetch_one(&db.0)
    .await?;

    Ok(rec)
}

pub async fn list_hospital_equipment(
    db: &Db,
    filter: EquipmentFilter,
) -> Result<Vec<HospitalEquipment>, DbError> {
    let mut qb = QueryBuilder::<Postgres>::new(
        r#"
        SELECT id, fixed_id, name, count, created_date, each_price, serial_no,
               purchase_date, equipment_type_id, org_id, report_id,
               is_active, created_doc_id, created_at, updated_at
        FROM public.hospital_equipment
        WHERE 1=1
        "#,
    );

    if let Some(n) = filter.name {
        qb.push(" AND name ILIKE ").push_bind(format!("%{}%", n));
    }
    if let Some(from) = filter.created_date_from {
        qb.push(" AND created_date >= ").push_bind(from);
    }
    if let Some(to) = filter.created_date_to {
        qb.push(" AND created_date <= ").push_bind(to);
    }
    if let Some(doc) = filter.created_doc_id {
        qb.push(" AND created_doc_id = ").push_bind(doc);
    }
    if let Some(active) = filter.is_active {
        qb.push(" AND is_active = ").push_bind(active);
    }
    if let Some(o) = filter.org_id {
        qb.push(" AND org_id = ").push_bind(o);
    }
    if let Some(t) = filter.equipment_type_id {
        qb.push(" AND equipment_type_id = ").push_bind(t);
    }
    if let Some(s) = filter.serial_no {
        qb.push(" AND serial_no ILIKE ")
            .push_bind(format!("%{}%", s));
    }

    let query = qb.build_query_as::<HospitalEquipment>();
    let recs = query.fetch_all(&db.0).await?;
    Ok(recs)
}

use sqlx::Arguments;
use sqlx::postgres::PgArguments;

pub async fn list_equipment_reports(
    db: &Db,
    report_id: Option<i64>,
    created_org_ids: Option<Vec<i32>>, // ✅ олон ID дэмжинэ
    created_doctor_id: Option<i64>,
    status: Option<String>,
    broken_date_from: Option<NaiveDate>,
    broken_date_to: Option<NaiveDate>,
    fixed_date_from: Option<NaiveDate>,
    fixed_date_to: Option<NaiveDate>,
) -> Result<Vec<EquipmentReport>, DbError> {
    let mut query = String::from("SELECT * FROM public.equipment_reports WHERE 1=1");
    let mut bind_args = PgArguments::default();
    let mut idx = 1;

    if let Some(r) = report_id {
        query.push_str(&format!(" AND report_id = ${}", idx));
        bind_args.add(r);
        idx += 1;
    }

    if let Some(org_ids) = created_org_ids {
        query.push_str(&format!(" AND created_org_id = ANY(${})", idx));
        bind_args.add(org_ids);
        idx += 1;
    }

    if let Some(d) = created_doctor_id {
        query.push_str(&format!(" AND created_doctor_id = ${}", idx));
        bind_args.add(d);
        idx += 1;
    }

    if let Some(s) = status {
        query.push_str(&format!(" AND status ILIKE ${}", idx));
        bind_args.add(format!("%{}%", s));
        idx += 1;
    }

    if let Some(from) = broken_date_from {
        query.push_str(&format!(" AND broken_date >= ${}", idx));
        bind_args.add(from);
        idx += 1;
    }
    if let Some(to) = broken_date_to {
        query.push_str(&format!(" AND broken_date <= ${}", idx));
        bind_args.add(to);
        idx += 1;
    }
    if let Some(from) = fixed_date_from {
        query.push_str(&format!(" AND fixed_date >= ${}", idx));
        bind_args.add(from);
        idx += 1;
    }
    if let Some(to) = fixed_date_to {
        query.push_str(&format!(" AND fixed_date <= ${}", idx));
        bind_args.add(to);
        idx += 1;
    }

    let rows = sqlx::query_as_with::<_, EquipmentReport, _>(&query, bind_args)
        .fetch_all(&db.0)
        .await?;

    Ok(rows)
}
pub async fn fixed_report_create(
    db: &Db,
    report_id: i64,
    reason: Option<&str>,
    fixed_date: NaiveDate,
    created_org_id: Option<i32>,
    created_doctor_id: Option<i64>,
) -> Result<Result<EquipmentReport, serde_json::Value>, DbError> {
    // Сүүлчийн report шалгах
    if let Some((status,)) = sqlx::query_as::<_, (Option<String>,)>(
        r#"
        SELECT status
        FROM public.equipment_reports
        WHERE report_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(report_id)
    .fetch_optional(&db.0)
    .await?
    {
        if let Some(s) = status {
            if s.to_lowercase() == "fixed" {
                // аль хэдийн fixed болчихсон бол → JSON мессеж буцаана
                let msg = serde_json::json!({
                    "message": "Тухайн төхөөрөмж хэвийн байна"
                });
                return Ok(Err(msg));
            }
        }
    }

    // Сүүлийн broken_date авах
    let last_broken: Option<Option<NaiveDate>> = sqlx::query_scalar!(
        r#"
        SELECT broken_date
        FROM public.equipment_reports
        WHERE report_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        report_id
    )
    .fetch_optional(&db.0)
    .await?;

    let broken_date = last_broken.flatten();

    // Шинэ мөр оруулах
    let rec = sqlx::query_as!(
        EquipmentReport,
        r#"
        INSERT INTO public.equipment_reports
            (report_id, issue_description, reason, broken_date, fixed_date, status, created_org_id, created_doctor_id)
        VALUES ($1, NULL, $2, $3, $4, 'fixed', $5, $6)
        RETURNING 
            id, report_id, issue_description, reason, broken_date, fixed_date, status,
            created_org_id, created_doctor_id, created_at, updated_at
        "#,
        report_id,
        reason,
        broken_date,
        fixed_date,
        created_org_id,
        created_doctor_id
    )
    .fetch_one(&db.0)
    .await?;

    // hospital_equipment → хэвийн болгож update хийх
    sqlx::query!(
        r#"UPDATE public.hospital_equipment SET is_active = true WHERE report_id = $1"#,
        report_id
    )
    .execute(&db.0)
    .await?;

    Ok(Ok(rec))
}

// ==== Refresh tokens (rotation) ====
#[derive(sqlx::FromRow, Debug, Clone, Serialize)]
pub struct RefreshRow {
    pub id: i64,
    pub user_id: Uuid,
    pub jti: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_refresh(
    db: &Db,
    user_id: Uuid,
    jti: &str,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<RefreshRow, DbError> {
    let row = sqlx::query_as::<_, RefreshRow>(
        r#"INSERT INTO refresh_tokens(user_id,jti,token_hash,expires_at)
        VALUES($1,$2,$3,$4) RETURNING id,user_id,jti,token_hash,expires_at,revoked,created_at"#,
    )
    .bind(user_id)
    .bind(jti)
    .bind(token_hash)
    .bind(expires_at)
    .fetch_one(&db.0)
    .await?;
    Ok(row)
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
