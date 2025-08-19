use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)]
pub struct Password(Secret<String>);

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Password {
    pub fn parse(s: Secret<String>) -> Result<Password> {
        if validate_password(&s) {
            Ok(Self(s))
        } else {
            Err(eyre!("Failed to parse string to a Password type"))
        }
    }
}

fn validate_password(s: &Secret<String>) -> bool {
    s.expose_secret().len() >= 8
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_password() {
        assert_eq!(
            "MySecretPassword",
            Password::parse(Secret::new("MySecretPassword".to_owned()))
                .unwrap()
                .0
                .expose_secret()
        )
    }

    #[test]
    fn parse_invalid_password() {
        assert!(Password::parse(Secret::new("pwd".to_owned())).is_err());
    }
}
