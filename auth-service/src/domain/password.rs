#[derive(Debug, PartialEq, Clone)]
pub struct Password(String);

impl Password {
    pub fn parse(password: &str) -> Result<Self, String> {
        match password.len() >= 8 {
            true => Ok(Password(password.to_owned())),
            false => Err("Invalid password".to_owned()),
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::password::Password;

    #[test]
    fn parse_valid_password() {
        assert_eq!(
            "MySecretPassword",
            Password::parse("MySecretPassword").unwrap().as_ref()
        )
    }

    #[test]
    fn parse_invalid_password() {
        assert!(Password::parse("pwd").is_err());
    }
}
