use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use configparser::ini::Ini;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileDefaults {
    pub compartment: Option<String>,
    pub subnet: Option<String>,
    pub shape: Option<String>,
    pub availability_domain: Option<String>,
    pub image: Option<String>,
    pub image_os: Option<String>,
    pub image_version: Option<String>,
    pub ssh_public_key: Option<String>,
    pub display_name_prefix: Option<String>,
    pub boot_volume_size_gbs: Option<u64>,
    pub boot_volume_vpus_per_gb: Option<u64>,
    pub ocpus: Option<f64>,
    pub memory_in_gbs: Option<f64>,
    pub root_login: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Preset {
    pub name: String,
    pub compartment: Option<String>,
    pub subnet: Option<String>,
    pub shape: Option<String>,
    pub availability_domain: Option<String>,
    pub image: Option<String>,
    pub image_os: Option<String>,
    pub image_version: Option<String>,
    pub ssh_public_key: Option<String>,
    pub display_name_prefix: Option<String>,
    pub boot_volume_size_gbs: Option<u64>,
    pub boot_volume_vpus_per_gb: Option<u64>,
    pub ocpus: Option<f64>,
    pub memory_in_gbs: Option<f64>,
    pub root_login: Option<bool>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct NotificationConfig {
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub discord_webhook_url: Option<String>,
    pub email_smtp_host: Option<String>,
    pub email_smtp_port: Option<u16>,
    pub email_username: Option<String>,
    pub email_password: Option<String>,
    pub email_from: Option<String>,
    pub email_to: Option<String>,
    pub email_use_tls: Option<bool>,
    pub email_subject_prefix: Option<String>,
}

impl NotificationConfig {
    pub fn from_props(props: &std::collections::HashMap<String, Option<String>>) -> Result<Self> {
        Ok(Self {
            telegram_bot_token: optional(props, "telegram_bot_token"),
            telegram_chat_id: optional(props, "telegram_chat_id"),
            discord_webhook_url: optional(props, "discord_webhook_url"),
            email_smtp_host: optional(props, "email_smtp_host"),
            email_smtp_port: optional_u64(props, "email_smtp_port")?.map(|v| v as u16),
            email_username: optional(props, "email_username"),
            email_password: optional(props, "email_password"),
            email_from: optional(props, "email_from"),
            email_to: optional(props, "email_to"),
            email_use_tls: optional_bool(props, "email_use_tls")?,
            email_subject_prefix: optional(props, "email_subject_prefix"),
        })
    }

    pub fn is_configured(&self) -> bool {
        self.telegram_bot_token.is_some()
            || self.discord_webhook_url.is_some()
            || self.email_configured()
    }

    pub fn email_configured(&self) -> bool {
        self.email_smtp_host.is_some() && self.email_from.is_some() && self.email_to.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub user: String,
    pub fingerprint: String,
    pub tenancy: String,
    pub region: String,
    pub key_file: PathBuf,
    pub defaults: ProfileDefaults,
    pub notify: NotificationConfig,
    pub admin_key: Option<String>,
    pub port: Option<u16>,
    pub enable_admin: bool,
}

#[derive(Debug)]
pub struct OciConfig {
    pub path: PathBuf,
    pub profiles: HashMap<String, Profile>,
    pub presets: Vec<Preset>,
    pub global_props: HashMap<String, Option<String>>,
}

impl OciConfig {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let path = path.unwrap_or_else(default_config_path);
        let mut ini = Ini::new();
        ini.set_default_section("DEFAULT");
        let map = ini
            .load(path.to_string_lossy().as_ref())
            .map_err(|err| anyhow::anyhow!("{}", err))
            .with_context(|| format!("Failed to load config file: {}", path.display()))?;
        let config_dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let mut profiles = HashMap::new();
        let mut presets = Vec::new();
        // Helper to collect global properties from "DEFAULT" and "global:web"
        let mut global_props = HashMap::new();

        // 1. Merge properties from DEFAULT (top-level keys)
        if let Some(default_map) = map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("DEFAULT"))
            .map(|(_, v)| v.clone())
        {
            for (k, v) in default_map {
                global_props.insert(k, v);
            }
        }

        // 2. Merge properties from [global:web], [global:notify], [global:telegram_bot]
        for section_name in ["global:web", "global:notify", "global:telegram_bot"] {
            if let Some(section_map) = map
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(section_name))
                .map(|(_, v)| v.clone())
            {
                for (k, v) in section_map {
                    global_props.insert(k, v);
                }
            }
        }

        for (section, props) in map.iter() {
            let name = section.to_string();

            // Skip processing global sections as profiles
            if ["global:web", "global:notify", "global:telegram_bot"]
                .iter()
                .any(|section| name.eq_ignore_ascii_case(section))
            {
                continue;
            }

            if let Some(preset_name) = name.strip_prefix("preset:") {
                let preset = Preset::from_props(preset_name.trim().to_string(), props)?;
                presets.push(preset);
            } else {
                // Merge global_props into this profile's props if keys are missing
                let mut merged_props = props.clone();
                for (k, v) in &global_props {
                    merged_props.entry(k.clone()).or_insert(v.clone());
                }

                // If this is the DEFAULT section, we still try to parse it as a profile
                // (it might contain the main credentials).
                // If it fails (e.g. missing 'user'), we ignore it (it was just global settings).
                if name.eq_ignore_ascii_case("DEFAULT") {
                    if let Ok(profile) = Profile::from_props(&merged_props, &config_dir) {
                        profiles.insert(name.to_uppercase(), profile);
                    }
                } else {
                    let profile = Profile::from_props(&merged_props, &config_dir)?;
                    profiles.insert(name.to_uppercase(), profile);
                }
            }
        }

        // if profiles.is_empty() {
        //     bail!("No profiles found in {}", path.display());
        // }

        presets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self {
            path,
            profiles,
            presets,
            global_props,
        })
    }

    pub fn profile(&self, name: Option<&str>) -> Result<Profile> {
        let key = name.unwrap_or("DEFAULT").to_uppercase();
        self.profiles
            .get(&key)
            .cloned()
            .with_context(|| format!("Profile '{}' not found in {}", key, self.path.display()))
    }
}

impl Preset {
    fn from_props(
        name: String,
        props: &std::collections::HashMap<String, Option<String>>,
    ) -> Result<Self> {
        Ok(Self {
            name,
            compartment: optional(props, "compartment"),
            subnet: optional(props, "subnet"),
            shape: optional(props, "shape"),
            availability_domain: optional(props, "availability_domain"),
            image: optional(props, "image"),
            image_os: optional(props, "image_os"),
            image_version: optional(props, "image_version"),
            ssh_public_key: optional(props, "ssh_public_key"),
            display_name_prefix: optional(props, "display_name_prefix"),
            boot_volume_size_gbs: optional_u64(props, "boot_volume_size_gbs")?,
            boot_volume_vpus_per_gb: optional_u64(props, "boot_volume_vpus_per_gb")?,
            ocpus: optional_f64(props, "ocpus")?,
            memory_in_gbs: optional_f64(props, "memory_in_gbs")?,
            root_login: optional_bool(props, "root_login")?,
        })
    }
}

impl Profile {
    fn from_props(
        props: &std::collections::HashMap<String, Option<String>>,
        config_dir: &Path,
    ) -> Result<Self> {
        let user = required(props, "user")?;
        let fingerprint = required(props, "fingerprint")?;
        let tenancy = required(props, "tenancy")?;
        let region = required(props, "region")?;
        let key_file_raw = required(props, "key_file")?;
        let key_file = resolve_path(config_dir, &key_file_raw);

        let defaults = ProfileDefaults {
            compartment: optional(props, "compartment"),
            subnet: optional(props, "subnet"),
            shape: optional(props, "shape"),
            availability_domain: optional(props, "availability_domain"),
            image: optional(props, "image"),
            image_os: optional(props, "image_os"),
            image_version: optional(props, "image_version"),
            ssh_public_key: optional(props, "ssh_public_key"),
            display_name_prefix: optional(props, "display_name_prefix"),
            boot_volume_size_gbs: optional_u64(props, "boot_volume_size_gbs")?,
            boot_volume_vpus_per_gb: optional_u64(props, "boot_volume_vpus_per_gb")?,
            ocpus: optional_f64(props, "ocpus")?,
            memory_in_gbs: optional_f64(props, "memory_in_gbs")?,
            root_login: optional_bool(props, "root_login")?,
        };

        let notify = NotificationConfig::from_props(props)?;
        let admin_key = optional(props, "admin_key");
        let port = optional_u64(props, "port")?.map(|v| v as u16);
        let enable_admin = props
            .get("enable_admin")
            .and_then(|v| v.as_deref())
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Ok(Self {
            user,
            fingerprint,
            tenancy,
            region,
            key_file,
            defaults,
            notify,
            admin_key,
            port,
            enable_admin,
        })
    }
}

fn default_config_path() -> PathBuf {
    // Prefer config in the current working directory
    let local = PathBuf::from("config");
    if local.exists() {
        return local;
    }
    // Fall back to ~/.oci/config
    if let Some(home) = dirs::home_dir() {
        return home.join(".oci").join("config");
    }
    local
}

fn required(
    props: &std::collections::HashMap<String, Option<String>>,
    key: &str,
) -> Result<String> {
    optional(props, key).ok_or_else(|| anyhow::anyhow!("Missing required key: {}", key))
}

fn optional(
    props: &std::collections::HashMap<String, Option<String>>,
    key: &str,
) -> Option<String> {
    find_value(props, key).map(|value| normalize_value(&value))
}

fn optional_u64(
    props: &std::collections::HashMap<String, Option<String>>,
    key: &str,
) -> Result<Option<u64>> {
    let Some(raw) = optional(props, key) else {
        return Ok(None);
    };
    let parsed = raw
        .parse::<u64>()
        .with_context(|| format!("Invalid integer for '{}': {}", key, raw))?;
    Ok(Some(parsed))
}

fn optional_bool(
    props: &std::collections::HashMap<String, Option<String>>,
    key: &str,
) -> Result<Option<bool>> {
    let Some(raw) = optional(props, key) else {
        return Ok(None);
    };
    let value = raw.to_lowercase();
    match value.as_str() {
        "true" | "1" | "yes" | "on" => Ok(Some(true)),
        "false" | "0" | "no" | "off" => Ok(Some(false)),
        _ => Err(anyhow::anyhow!("Invalid boolean for '{}': {}", key, raw)),
    }
}

fn optional_f64(
    props: &std::collections::HashMap<String, Option<String>>,
    key: &str,
) -> Result<Option<f64>> {
    let Some(raw) = optional(props, key) else {
        return Ok(None);
    };
    let parsed = raw
        .parse::<f64>()
        .with_context(|| format!("Invalid float for '{}': {}", key, raw))?;
    Ok(Some(parsed))
}

fn find_value(
    props: &std::collections::HashMap<String, Option<String>>,
    key: &str,
) -> Option<String> {
    if let Some(value) = props.get(key) {
        return value.clone();
    }
    let key_lower = key.to_lowercase();
    for (prop_key, value) in props {
        if prop_key.to_lowercase() == key_lower {
            return value.clone();
        }
    }
    None
}

fn normalize_value(value: &str) -> String {
    let trimmed = value.trim();
    let no_comment = trimmed
        .split('#')
        .next()
        .unwrap_or(trimmed)
        .split(';')
        .next()
        .unwrap_or(trimmed)
        .trim();
    no_comment.to_string()
}

fn resolve_path(config_dir: &Path, value: &str) -> PathBuf {
    let expanded = expand_tilde(value);
    let path = PathBuf::from(expanded);
    if path.is_relative() {
        config_dir.join(path)
    } else {
        path
    }
}

fn expand_tilde(value: &str) -> String {
    if let Some(stripped) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped).to_string_lossy().to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn load_profiles_and_defaults() {
        let temp_dir = std::env::temp_dir().join("oci_manager_test");
        let _ = fs::create_dir_all(&temp_dir);
        let config_path = temp_dir.join("config");
        let content = r#"
[DEFAULT]
user=ocid1.user.oc1..example
fingerprint=aa:bb:cc
tenancy=ocid1.tenancy.oc1..example
region=us-phoenix-1
key_file=oci.pem
compartment=ocid1.compartment.oc1..example
enable_admin=true
admin_key=secret
        "#;
        fs::write(&config_path, content).expect("write config");
        let cfg = OciConfig::load(Some(config_path.clone())).expect("load");
        let profile = cfg.profile(Some("DEFAULT")).expect("profile");
        assert_eq!(profile.user, "ocid1.user.oc1..example");
        assert_eq!(
            profile.defaults.compartment.as_deref(),
            Some("ocid1.compartment.oc1..example")
        );
        assert!(profile.key_file.ends_with("oci.pem"));
        assert_eq!(profile.admin_key.as_deref(), Some("secret"));
        assert!(profile.enable_admin);
    }

    #[test]
    fn load_notification_config() {
        let temp_dir = std::env::temp_dir().join("oci_manager_test_notify");
        let _ = fs::create_dir_all(&temp_dir);
        let config_path = temp_dir.join("config");
        let content = r#"
[global:telegram_bot]
telegram_bot_token=bot-token

[global:notify]
telegram_chat_id=12345
discord_webhook_url=https://discord.com/api/webhooks/test
email_smtp_host=smtp.example.com
email_smtp_port=587
email_from=oci@example.com
email_to=ops@example.com
email_use_tls=true

[DEFAULT]
user=ocid1.user.oc1..example
fingerprint=aa:bb:cc
tenancy=ocid1.tenancy.oc1..example
region=us-ashburn-1
key_file=oci.pem
        "#;
        fs::write(&config_path, content).expect("write config");
        let cfg = OciConfig::load(Some(config_path)).expect("load");
        let profile = cfg.profile(Some("DEFAULT")).expect("profile");
        assert_eq!(
            profile.notify.telegram_bot_token.as_deref(),
            Some("bot-token")
        );
        assert_eq!(profile.notify.telegram_chat_id.as_deref(), Some("12345"));
        assert!(profile.notify.email_configured());
        assert_eq!(profile.notify.email_use_tls, Some(true));
    }
}
