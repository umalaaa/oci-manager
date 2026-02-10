use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
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
    pub ocpus: Option<f64>,
    pub memory_in_gbs: Option<f64>,
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
    pub ocpus: Option<f64>,
    pub memory_in_gbs: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub user: String,
    pub fingerprint: String,
    pub tenancy: String,
    pub region: String,
    pub key_file: PathBuf,
    pub defaults: ProfileDefaults,
    pub admin_key: Option<String>,
    pub port: Option<u16>,
    pub enable_admin: bool,
}

#[derive(Debug)]
pub struct OciConfig {
    pub path: PathBuf,
    pub profiles: HashMap<String, Profile>,
    pub presets: Vec<Preset>,
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
        // Helper to find the "DEFAULT" section regardless of case
        let default_props = map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("DEFAULT"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        for (section, props) in map.iter() {
            let name = section.to_string();
            // skip processing the DEFAULT section itself as a profile,
            // unless we want it to be a valid profile.
            // Usually [DEFAULT] is just for inheritance, but if it contains user/tenancy calls...
            // Let's treat it as a profile effectively if it has enough info,
            // OR just use it to backfill others.

            if let Some(preset_name) = name.strip_prefix("preset:") {
                let preset = Preset::from_props(preset_name.trim().to_string(), props)?;
                presets.push(preset);
            } else {
                // Merge default_props into this profile's props if keys are missing
                let mut merged_props = props.clone();
                for (k, v) in &default_props {
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

        if profiles.is_empty() {
            bail!("No profiles found in {}", path.display());
        }

        presets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self {
            path,
            profiles,
            presets,
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
            ocpus: optional_f64(props, "ocpus")?,
            memory_in_gbs: optional_f64(props, "memory_in_gbs")?,
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
            ocpus: optional_f64(props, "ocpus")?,
            memory_in_gbs: optional_f64(props, "memory_in_gbs")?,
        };

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
}
