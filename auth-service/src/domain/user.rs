use getset::Getters;

use crate::{
    domain::{Email, Password, UserStoreError},
    services::PgUser,
};

#[derive(Clone, Getters, PartialEq, Debug)]
pub struct User {
    #[get = "pub"]
    email: Email,
    #[get = "pub"]
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
            false => Err(UserStoreError::InvalidCredentials),
        }
    }
}

impl From<PgUser> for User {
    fn from(pg_user: PgUser) -> Self {
        User {
            email: Email::parse(&pg_user.email).unwrap(),
            password: Password::parse(&pg_user.password_hash).unwrap(),
            requires_2fa: pg_user.requires_2fa,
        }
    }
}
