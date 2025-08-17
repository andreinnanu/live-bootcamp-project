use std::error::Error;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};

use sqlx::{prelude::FromRow, PgPool};

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User,
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
pub struct PgUser {
    pub email: String,
    pub password_hash: String,
    pub requires_2fa: bool,
}

impl PostgresUserStore {
    async fn get_pg_user(&self, email: Email) -> Result<PgUser, UserStoreError> {
        let result: Option<PgUser> =
            sqlx::query_as("SELECT email, password_hash, requires_2fa FROM users WHERE email = $1")
                .bind(email.as_ref())
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| UserStoreError::UnexpectedError)?;

        match result {
            Some(pg_user) => Ok(pg_user),
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let owned_pwd = user.password().as_ref().to_owned();
        let hashed_pwd = tokio::task::spawn_blocking(move || {
            compute_password_hash(owned_pwd).map_err(|_| UserStoreError::UnexpectedError)
        })
        .await
        .map_err(|_| UserStoreError::UnexpectedError)??;

        let result = sqlx::query(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
        )
        .bind(user.email().as_ref())
        .bind(hashed_pwd)
        .bind(user.requires_2fa())
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) => {
                if db_err.is_unique_violation() {
                    return Err(UserStoreError::UserAlreadyExists);
                }
                Err(UserStoreError::UnexpectedError)
            }
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    async fn get_user(&self, email: Email) -> Result<User, UserStoreError> {
        Ok(User::from(self.get_pg_user(email).await?))
    }

    async fn validate_user(&self, email: Email, password: Password) -> Result<(), UserStoreError> {
        let user = self.get_pg_user(email.clone()).await?;

        tokio::task::spawn_blocking(move || {
            verify_password_hash(user.password_hash, password.as_ref().to_owned())
                .map_err(|_| UserStoreError::UnexpectedError)
        })
        .await
        .map_err(|_| UserStoreError::InvalidCredentials)?
    }
}

fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error>> {
    let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&expected_password_hash)?;

    Argon2::default()
        .verify_password(password_candidate.as_bytes(), &expected_password_hash)
        .map_err(|e| e.into())
}

fn compute_password_hash(password: String) -> Result<String, Box<dyn Error>> {
    let salt: SaltString = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None)?,
    )
    .hash_password(password.as_bytes(), &salt)?
    .to_string();

    Ok(password_hash)
}
