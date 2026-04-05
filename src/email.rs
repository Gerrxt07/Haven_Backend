use crate::{config::Config, error::AppError};
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

#[derive(Clone)]
pub struct EmailClient {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl EmailClient {
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

        let builder = if config.smtp_use_starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
        };

        let mailer = builder
            .port(config.smtp_port)
            .credentials(creds)
            .build();

        let from = Mailbox::new(
            Some(config.smtp_from_name.clone()),
            config.smtp_from_email.parse()?,
        );

        Ok(Self { mailer, from })
    }

    pub async fn send_verification_code(
        &self,
        to_email: &str,
        code: &str,
        ttl_minutes: i64,
    ) -> Result<(), AppError> {
        let to: Mailbox = to_email
            .parse()
            .map_err(|_| AppError::BadRequest("invalid email address".to_string()))?;

        let subject = "Verify your Haven email";
        let text_body = format!(
            "Your Haven verification code is {code}.\n\nThis code expires in {ttl_minutes} minutes."
        );

        let html_body = build_verification_email_html(code, ttl_minutes);

        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(text_body))
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )
            .map_err(|_| AppError::Service("failed to build verification email".to_string()))?;

        self.mailer
            .send(message)
            .await
            .map_err(|_| AppError::Service("failed to send verification email".to_string()))?;

        Ok(())
    }
}

fn build_verification_email_html(code: &str, ttl_minutes: i64) -> String {
    let logo_url = "https://raw.githubusercontent.com/Gerrxt07/Haven/refs/heads/master/public/logo.png";
    let banner_url = "https://raw.githubusercontent.com/Gerrxt07/Haven/refs/heads/master/public/form_background.png";

    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify your Haven email</title>
</head>
<body style="margin:0;background:#0b0f16;font-family:Arial,Helvetica,sans-serif;color:#e6ecf5;">
  <div style="width:100%;padding:28px 16px 40px 16px;box-sizing:border-box;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;margin:0 auto;border-radius:18px;background:#111827;border:1px solid #1f2937;overflow:hidden;">
      <tr>
        <td style="padding:24px 28px 8px 28px;text-align:center;">
          <img src="{logo_url}" alt="Haven" width="120" style="display:block;margin:0 auto 10px auto;">
          <div style="font-size:20px;font-weight:700;letter-spacing:0.5px;">Verify your email</div>
          <div style="font-size:14px;color:#94a3b8;margin-top:6px;">Use this code to finish signing in.</div>
        </td>
      </tr>
      <tr>
        <td style="padding:18px 28px 24px 28px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-radius:14px;overflow:hidden;background:#0b0f16;">
            <tr>
              <td style="background-image:url('{banner_url}');background-size:cover;background-position:center;padding:36px 16px;text-align:center;">
                <div style="display:inline-block;padding:14px 26px;border-radius:12px;background:rgba(11,15,22,0.75);border:1px solid rgba(148,163,184,0.25);font-size:28px;letter-spacing:6px;font-weight:700;color:#f8fafc;">
                  {code}
                </div>
              </td>
            </tr>
          </table>
          <div style="margin-top:16px;font-size:13px;color:#94a3b8;text-align:center;">
            Code expires in {ttl_minutes} minutes. If you did not request this, you can ignore this email.
          </div>
        </td>
      </tr>
    </table>
  </div>
</body>
</html>"#,
        logo_url = logo_url,
        banner_url = banner_url,
        code = code,
        ttl_minutes = ttl_minutes
    )
}
