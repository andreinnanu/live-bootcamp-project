use std::collections::HashMap;

use crate::domain::{email::Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes
            .get(email)
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore},
        services::HashmapTwoFACodeStore,
    };

    #[tokio::test]
    async fn add_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let login_attempt_id = LoginAttemptId::default();
        let two_facode = TwoFACode::default();
        let _ = store
            .add_code(
                Email::parse("test@email.com").unwrap(),
                login_attempt_id.clone(),
                two_facode.clone(),
            )
            .await;

        assert_eq!(
            store.codes,
            HashMap::from([(
                Email::parse("test@email.com").unwrap(),
                (login_attempt_id, two_facode)
            )])
        );
    }

    #[tokio::test]
    async fn get_code_found() {
        let mut store = HashmapTwoFACodeStore::default();
        let login_attempt_id = LoginAttemptId::default();
        let two_facode = TwoFACode::default();
        let email = Email::parse("test@email.com").unwrap();

        let _ = store
            .add_code(email.clone(), login_attempt_id.clone(), two_facode.clone())
            .await;

        assert_eq!(
            store.get_code(&email).await.unwrap(),
            (login_attempt_id, two_facode)
        );
    }

    #[tokio::test]
    async fn get_code_not_found() {
        let mut store = HashmapTwoFACodeStore::default();
        let login_attempt_id = LoginAttemptId::default();
        let two_facode = TwoFACode::default();
        let email = Email::parse("test@email.com").unwrap();

        let _ = store
            .add_code(email.clone(), login_attempt_id.clone(), two_facode.clone())
            .await;

        assert_eq!(
            store
                .get_code(&Email::parse("not_test@email.com").unwrap())
                .await,
            Err(crate::domain::TwoFACodeStoreError::LoginAttemptIdNotFound)
        );
    }

    #[tokio::test]
    async fn remove_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let login_attempt_id = LoginAttemptId::default();
        let two_facode = TwoFACode::default();
        let email = Email::parse("test@email.com").unwrap();

        let _ = store
            .add_code(email.clone(), login_attempt_id.clone(), two_facode.clone())
            .await;

        assert_eq!(
            store
                .get_code(&Email::parse("test@email.com").unwrap())
                .await
                .unwrap(),
            (login_attempt_id, two_facode)
        );

        let _ = store.remove_code(&email).await;

        assert_eq!(
            store
                .get_code(&Email::parse("test@email.com").unwrap())
                .await,
            Err(crate::domain::TwoFACodeStoreError::LoginAttemptIdNotFound)
        );
    }
}
