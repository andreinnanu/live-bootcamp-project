use std::collections::{hash_map::Entry, HashMap};

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

#[derive(Default, PartialEq, Debug)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        match self.users.entry(user.email().to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(user);
                Ok(())
            }
            Entry::Occupied(_) => Err(UserStoreError::UserAlreadyExists),
        }
    }

    async fn get_user(&self, email: Email) -> Result<User, UserStoreError> {
        self.users
            .get(&email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: Email, password: Password) -> Result<(), UserStoreError> {
        self.get_user(email).await?.validate_password(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use secrecy::Secret;

    static TEST_USER: Lazy<User> = Lazy::new(|| {
        User::new(
            Email::parse("abc@test.com").unwrap(),
            Password::parse(Secret::new("MySecretPassword".to_owned())).unwrap(),
            false,
        )
    });

    #[tokio::test]
    async fn test_add_user() {
        let mut hashmap_user_store = HashmapUserStore::default();

        assert_eq!(hashmap_user_store.add_user(TEST_USER.clone()).await, Ok(()));

        assert_eq!(
            HashMap::from([(TEST_USER.email().to_owned(), TEST_USER.clone())]),
            hashmap_user_store.users
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        hashmap_user_store
            .add_user(TEST_USER.clone())
            .await
            .unwrap();
        assert_eq!(
            TEST_USER.clone(),
            hashmap_user_store
                .get_user(TEST_USER.email().to_owned())
                .await
                .unwrap()
        );
        assert_eq!(
            Err(UserStoreError::UserNotFound),
            hashmap_user_store
                .get_user(Email::parse("not_found@test.com").unwrap())
                .await
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hashmap_user_store = HashmapUserStore::default();
        hashmap_user_store
            .add_user(TEST_USER.clone())
            .await
            .unwrap();

        assert_eq!(
            Ok(()),
            hashmap_user_store
                .validate_user(
                    TEST_USER.email().to_owned(),
                    Password::parse(Secret::new("MySecretPassword".to_owned())).unwrap()
                )
                .await
        );
        assert_eq!(
            Err(UserStoreError::InvalidCredentials),
            hashmap_user_store
                .validate_user(
                    TEST_USER.email().to_owned(),
                    Password::parse(Secret::new("NotMySecretPassword".to_owned())).unwrap()
                )
                .await
        );
    }
}
