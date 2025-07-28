use getset::Getters;

use crate::domain::{Email, Password, UserStoreError};

// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.

#[derive(Clone, Getters, PartialEq, Debug)]
pub struct User {
    #[get = "pub"]
    email: Email,
    password: Password,
    #[get = "pub"]
    requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        User {
            email,
            password,
            requires_2fa,
        }
    }

    pub fn validate_password(&self, password: Password) -> Result<(), UserStoreError> {
        match self.password == password {
            true => Ok(()),
            false => Err(UserStoreError::InvalidCredentials)
        }
    }
}
