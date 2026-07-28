use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{error, info, warn};

/// Outbound mail.
///
/// The mail server runs on the same host, so the default is a plain SMTP hop
/// to `localhost` with no auth — TLS on a loopback connection buys nothing and
/// costs a certificate. Set `SMTP_USER`/`SMTP_PASS` (and `SMTP_STARTTLS=1`)
/// when pointing this at a relay somewhere else.
///
/// With `SMTP_HOST` unset the mailer is simply disabled: sends are logged and
/// dropped instead of failing the request that triggered them. A newsletter
/// signup is still recorded in that case — it just stays unconfirmed until
/// mail works.
#[derive(Clone)]
pub struct Mailer {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: Mailbox,
    pub base_url: String,
}

impl Mailer {
    pub fn from_env() -> Self {
        let from: Mailbox = std::env::var("MAIL_FROM")
            .unwrap_or_else(|_| "Honmoon <newsletter@honmoon.app>".to_string())
            .parse()
            .unwrap_or_else(|e| {
                warn!("MAIL_FROM is not a valid address ({e}), falling back");
                "newsletter@honmoon.app".parse().unwrap()
            });

        let base_url = std::env::var("PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "https://sync.honmoon.app".to_string());

        let transport = match std::env::var("SMTP_HOST") {
            Ok(host) if !host.is_empty() => {
                let port: u16 = std::env::var("SMTP_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(25);

                let starttls = matches!(
                    std::env::var("SMTP_STARTTLS").as_deref(),
                    Ok("1") | Ok("true")
                );

                let builder = if starttls {
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                        .map(|b| b.port(port))
                } else {
                    Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host).port(port))
                };

                match builder {
                    Ok(mut b) => {
                        if let (Ok(user), Ok(pass)) =
                            (std::env::var("SMTP_USER"), std::env::var("SMTP_PASS"))
                        {
                            if !user.is_empty() {
                                b = b.credentials(Credentials::new(user, pass));
                            }
                        }
                        info!("Mailer enabled via {host}:{port} (starttls={starttls})");
                        Some(b.build())
                    }
                    Err(e) => {
                        error!("SMTP transport could not be built: {e}");
                        None
                    }
                }
            }
            _ => {
                warn!("SMTP_HOST not set — outgoing mail is disabled");
                None
            }
        };

        Self {
            transport,
            from,
            base_url,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.transport.is_some()
    }

    /// Send a text+HTML mail. Never propagates a transport failure to the
    /// caller: mail is best-effort, and a bounced newsletter confirmation must
    /// not turn a signup into a 500.
    pub async fn send(&self, to: &str, subject: &str, text: String, html: String) -> bool {
        let Some(transport) = &self.transport else {
            info!("mail suppressed (mailer disabled): to={to} subject={subject}");
            return false;
        };

        let to_box: Mailbox = match to.parse() {
            Ok(m) => m,
            Err(e) => {
                warn!("refusing to mail invalid address {to}: {e}");
                return false;
            }
        };

        let message = match Message::builder()
            .from(self.from.clone())
            .to(to_box)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            ) {
            Ok(m) => m,
            Err(e) => {
                error!("could not build mail for {to}: {e}");
                return false;
            }
        };

        match transport.send(message).await {
            Ok(_) => {
                info!("mail sent: to={to} subject={subject}");
                true
            }
            Err(e) => {
                error!("mail to {to} failed: {e}");
                false
            }
        }
    }
}
