use std::sync::Arc;

use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let two_fa_tuple = TwoFATuple(
            login_attempt_id.as_ref().to_owned(),
            code.as_ref().to_owned(),
        );

        let serialized_tuple = serde_json::to_string(&two_fa_tuple)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(self
            .conn
            .write()
            .await
            .set_ex(get_key(&email), serialized_tuple, TEN_MINUTES_IN_SECONDS)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?)
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        Ok(self
            .conn
            .write()
            .await
            .del(get_key(email))
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?)
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let serialized_tuple: String = self
            .conn
            .write()
            .await
            .get(get_key(email))
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let deserialized_tuple: TwoFATuple = serde_json::from_str(&serialized_tuple)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok((
            LoginAttemptId::parse(deserialized_tuple.0)
                .map_err(|_| TwoFACodeStoreError::UnexpectedError)?,
            TwoFACode::parse(deserialized_tuple.1)
                .map_err(|_| TwoFACodeStoreError::UnexpectedError)?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
