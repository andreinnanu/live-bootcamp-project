#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: &str) -> Result<Self, String> {
        match email.contains('@') {
            true => Ok(Email(email.to_owned())),
            false => Err("Invalid email".to_owned()),
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::email::Email;

    #[test]
    fn parse_valid_email() {
        assert_eq!(
            "valid@email.com",
            Email::parse("valid@email.com").unwrap().as_ref()
        )
    }

    #[test]
    fn parse_invalid_email() {
        assert!(Email::parse("invalidemail.com").is_err());
    }
}
