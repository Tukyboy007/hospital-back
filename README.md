# Mono-Tumedu-Back

cargo sqlx prepare --workspace --database-url "postgres://postgres:postgres@192.168.99.209:5432/hospital-db"

cargo test -p api --test auth_test -- --nocapture
