use color_eyre::eyre::Result;
use crate::domain::{Email, EmailClient};

#[derive(Default)]
pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    #[tracing::instrument(name = "Sending 2FA email", skip(self))]
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<()> {
        // Our mock email client will simply log the recipient, subject, and content to standard output
        println!(
            "Sending email to {} with subject: {} and content: {}",
            recipient.as_ref(),
            subject,
            content
        );

        Ok(())
    }
}
