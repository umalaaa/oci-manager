use std::fs::OpenOptions;
use std::io::Write;

use anyhow::Result;
use reqwest::Client;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::warn;

use crate::config::{NotificationConfig, Profile};
use crate::models::InstanceSummary;
use crate::telegram_bind;

#[derive(Debug, Clone, Copy)]
pub enum NotifySource {
    Cli,
    Cron,
    Web,
    Task,
}

pub async fn notify_success(
    profile: &Profile,
    instance: &InstanceSummary,
    source: NotifySource,
    root_password: Option<&str>,
) {
    if let Some(password) = root_password {
        if let Err(err) = record_root_password(profile, instance, source, password) {
            warn!("Record root password failed: {}", err);
        }
    }

    let config = &profile.notify;
    if !config.is_configured() {
        return;
    }

    let message = build_message(profile, instance, source, root_password);
    if let Some(bot_token) = config.telegram_bot_token.as_deref() {
        let bound_chat_id = telegram_bind::load_chat_id().map(|id| id.to_string());
        let chat_id = bound_chat_id.or_else(|| config.telegram_chat_id.clone());
        if let Some(chat_id) = chat_id.as_deref() {
            if let Err(err) = send_telegram(bot_token, chat_id, &message).await {
                warn!("Telegram notification failed: {}", err);
            }
        } else {
            warn!("Telegram notification skipped: missing telegram_chat_id");
        }
    }

    if let Some(webhook_url) = config.discord_webhook_url.as_deref() {
        if let Err(err) = send_discord(webhook_url, &message).await {
            warn!("Discord notification failed: {}", err);
        }
    }

    if config.email_configured() {
        if let Err(err) = send_email(config, &message).await {
            warn!("Email notification failed: {}", err);
        }
    }
}

fn build_message(
    profile: &Profile,
    instance: &InstanceSummary,
    source: NotifySource,
    root_password: Option<&str>,
) -> String {
    let source_label = source_label(source);
    let mut message = format!(
        "OCI instance created ({source}): {name} ({id})\nRegion: {region}\nAD: {ad}\nShape: {shape}",
        source = source_label,
        name = instance.display_name,
        id = instance.id,
        region = profile.region,
        ad = instance.availability_domain,
        shape = instance.shape
    );
    if let Some(password) = root_password {
        message.push_str(&format!("\nRoot password: {}", password));
    }
    message
}

fn record_root_password(
    profile: &Profile,
    instance: &InstanceSummary,
    source: NotifySource,
    password: &str,
) -> Result<()> {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "now".to_string());
    let entry = serde_json::json!({
        "time": timestamp,
        "source": source_label(source),
        "region": profile.region,
        "availability_domain": instance.availability_domain,
        "shape": instance.shape,
        "instance_id": instance.id,
        "display_name": instance.display_name,
        "root_password": password,
    });
    std::fs::create_dir_all("data")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("data/root-passwords.log")?;
    writeln!(file, "{}", entry.to_string())?;
    Ok(())
}

fn source_label(source: NotifySource) -> &'static str {
    match source {
        NotifySource::Cli => "cli",
        NotifySource::Cron => "cron",
        NotifySource::Web => "web",
        NotifySource::Task => "task",
    }
}

async fn send_telegram(bot_token: &str, chat_id: &str, message: &str) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": message,
    });
    let client = Client::new();
    let response = client.post(url).json(&payload).send().await?;
    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow::anyhow!("telegram error {}: {}", status, body))
    }
}

async fn send_discord(webhook_url: &str, message: &str) -> Result<()> {
    let payload = serde_json::json!({ "content": message });
    let client = Client::new();
    let response = client.post(webhook_url).json(&payload).send().await?;
    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow::anyhow!("discord error {}: {}", status, body))
    }
}

async fn send_email(config: &NotificationConfig, message: &str) -> Result<()> {
    use lettre::message::Mailbox;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let host = match config.email_smtp_host.as_deref() {
        Some(value) => value,
        None => {
            return Err(anyhow::anyhow!(
                "email_smtp_host is required for email notifications"
            ))
        }
    };
    let port = config.email_smtp_port.unwrap_or(587);
    let from = match config.email_from.as_deref() {
        Some(value) => value,
        None => {
            return Err(anyhow::anyhow!(
                "email_from is required for email notifications"
            ))
        }
    };
    let to_list = match config.email_to.as_deref() {
        Some(value) => value,
        None => {
            return Err(anyhow::anyhow!(
                "email_to is required for email notifications"
            ))
        }
    };

    let mut builder = Message::builder().from(from.parse::<Mailbox>()?);
    for recipient in split_recipients(to_list) {
        builder = builder.to(recipient.parse::<Mailbox>()?);
    }

    let subject_prefix = config.email_subject_prefix.as_deref().unwrap_or("OCI");
    let subject = format!("{} instance created", subject_prefix);
    let email = builder.subject(subject).body(message.to_string())?;

    let mut transport = if config.email_use_tls.unwrap_or(true) {
        AsyncSmtpTransport::<Tokio1Executor>::relay(host)?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
    };
    transport = transport.port(port);

    if let Some(username) = config.email_username.as_deref() {
        let password = config.email_password.clone().unwrap_or_default();
        transport = transport.credentials(Credentials::new(username.to_string(), password));
    }

    transport.build().send(email).await?;
    Ok(())
}

fn split_recipients(value: &str) -> Vec<String> {
    value
        .split(&[',', ';', '\n'][..])
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_recipients_handles_separators() {
        let items = split_recipients("a@b.com,b@c.com; c@d.com\n\n");
        assert_eq!(items, vec!["a@b.com", "b@c.com", "c@d.com"]);
    }
}
