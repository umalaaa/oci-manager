use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::ProfileDefaults;
use crate::models::ImageSummary;
use crate::oci::OciClient;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CreateInput {
    pub profile: Option<String>,
    pub compartment: Option<String>,
    pub subnet: Option<String>,
    pub shape: Option<String>,
    pub ocpus: Option<f64>,
    pub memory_in_gbs: Option<f64>,
    pub boot_volume_size_gbs: Option<u64>,
    pub availability_domain: Option<String>,
    pub image: Option<String>,
    pub image_os: Option<String>,
    pub image_version: Option<String>,
    pub display_name: Option<String>,
    pub ssh_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedCreate {
    pub shape: String,
    pub availability_domain: String,
    pub payload: serde_json::Value,
}

pub async fn resolve_create_payload(
    client: &OciClient,
    defaults: &ProfileDefaults,
    input: CreateInput,
    allow_ssh_key_file: bool,
) -> Result<ResolvedCreate> {
    let compartment = input
        .compartment
        .or_else(|| defaults.compartment.clone())
        .ok_or_else(|| anyhow::anyhow!("Missing compartment OCID"))?;
    let subnet = input
        .subnet
        .or_else(|| defaults.subnet.clone())
        .ok_or_else(|| anyhow::anyhow!("Missing subnet OCID"))?;

    let availability_domain = match input
        .availability_domain
        .or_else(|| defaults.availability_domain.clone())
    {
        Some(ad) => ad,
        None => {
            let ads = client.availability_domains(&compartment).await?;
            ads.first()
                .map(|ad| ad.name.clone())
                .ok_or_else(|| anyhow::anyhow!("No availability domains found"))?
        }
    };

    let shape = match input.shape.or_else(|| defaults.shape.clone()) {
        Some(shape) => shape,
        None => pick_shape(client, &compartment, &availability_domain).await?,
    };

    let image = match input.image.or_else(|| defaults.image.clone()) {
        Some(image) => image,
        None => {
            let os = input
                .image_os
                .or_else(|| defaults.image_os.clone())
                .unwrap_or_else(|| "Oracle Linux".to_string());
            let version = input
                .image_version
                .or_else(|| defaults.image_version.clone());
            let images = client
                .list_images(&compartment, &shape, Some(&os), version.as_deref())
                .await?;
            select_latest_image(images)?
        }
    };

    let display_name = input.display_name.unwrap_or_else(|| {
        let prefix = defaults
            .display_name_prefix
            .clone()
            .unwrap_or_else(|| "auto".to_string());
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "now".to_string());
        format!("{}-{}", prefix, timestamp.replace(':', ""))
    });

    let ssh_key = resolve_ssh_key(
        input.ssh_key.or_else(|| defaults.ssh_public_key.clone()),
        allow_ssh_key_file,
    )?;

    let boot_volume_size_gbs = input.boot_volume_size_gbs.or(defaults.boot_volume_size_gbs);
    if let Some(size) = boot_volume_size_gbs {
        if size == 0 {
            bail!("boot volume size must be greater than 0");
        }
    }

    let mut ocpus = input.ocpus.or(defaults.ocpus);
    let mut memory_in_gbs = input.memory_in_gbs.or(defaults.memory_in_gbs);

    let is_flex = shape.to_uppercase().contains(".FLEX");

    // For flex shapes, both ocpus and memory_in_gbs are required.
    // If only one is set, infer the other. If neither, use safe defaults.
    if is_flex {
        match (ocpus, memory_in_gbs) {
            (None, None) => {
                tracing::info!(
                    "Flex shape with no ocpus/memory specified; defaulting to 1 OCPU, 6 GB"
                );
                ocpus = Some(1.0);
                memory_in_gbs = Some(6.0);
            }
            (Some(o), None) => {
                let mem = o * 6.0;
                tracing::info!(
                    "Flex shape: ocpus={} set but no memory; defaulting memory to {} GB",
                    o,
                    mem
                );
                memory_in_gbs = Some(mem);
            }
            (None, Some(m)) => {
                let cpu = (m / 6.0).max(1.0);
                tracing::info!(
                    "Flex shape: memory={} GB set but no ocpus; defaulting ocpus to {}",
                    m,
                    cpu
                );
                ocpus = Some(cpu);
            }
            (Some(_), Some(_)) => { /* both set, nothing to do */ }
        }
    } else if ocpus.is_some() ^ memory_in_gbs.is_some() {
        // Non-flex shape with partial flex config — just ignore both
        tracing::warn!(
            "Non-flex shape with partial ocpus/memory (ocpus={:?}, mem={:?}); ignoring both",
            ocpus,
            memory_in_gbs
        );
        ocpus = None;
        memory_in_gbs = None;
    }

    let mut payload = json!({
        "compartmentId": compartment,
        "availabilityDomain": availability_domain,
        "shape": shape,
        "displayName": display_name,
        "sourceDetails": {
            "sourceType": "image",
            "imageId": image,
        },
        "createVnicDetails": {
            "subnetId": subnet,
        }
    });

    if let (Some(ocpus), Some(memory)) = (ocpus, memory_in_gbs) {
        payload["shapeConfig"] = json!({
            "ocpus": ocpus,
            "memoryInGBs": memory
        });
    }

    if let Some(size) = boot_volume_size_gbs {
        payload["sourceDetails"]["bootVolumeSizeInGBs"] = json!(size);
    }

    if let Some(key) = ssh_key.as_ref() {
        payload["metadata"] = json!({ "ssh_authorized_keys": key });
    }

    Ok(ResolvedCreate {
        shape: payload["shape"].as_str().unwrap().to_string(),
        availability_domain: payload["availabilityDomain"].as_str().unwrap().to_string(),
        payload,
    })
}

async fn pick_shape(client: &OciClient, compartment: &str, ad: &str) -> Result<String> {
    let shapes = client.list_shapes(compartment, ad).await?;
    if shapes.is_empty() {
        bail!("No shapes available in {}", ad);
    }
    let preferred = shapes.iter().find(|shape| shape.shape.starts_with("VM."));
    Ok(preferred.unwrap_or(&shapes[0]).shape.to_string())
}

fn select_latest_image(images: Vec<ImageSummary>) -> Result<String> {
    if images.is_empty() {
        bail!("No images available for selected shape");
    }
    let mut images = images;
    images.sort_by(|a, b| {
        let a_time = parse_time(a);
        let b_time = parse_time(b);
        a_time.cmp(&b_time)
    });
    Ok(images
        .last()
        .map(|img| img.id.clone())
        .unwrap_or_else(|| images[0].id.clone()))
}

fn parse_time(image: &ImageSummary) -> OffsetDateTime {
    if let Some(value) = image.time_created.as_deref() {
        if let Ok(time) = OffsetDateTime::parse(value, &Rfc3339) {
            return time;
        }
    }
    OffsetDateTime::UNIX_EPOCH
}

fn resolve_ssh_key(value: Option<String>, allow_file: bool) -> Result<Option<String>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let mut keys = Vec::new();
    if !allow_file {
        for part in split_keys(&raw) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if !looks_like_ssh_key(part) {
                bail!("ssh_key must be an inline public key (paste the key contents).");
            }
            keys.push(part.to_string());
        }
        return Ok(dedupe_keys(keys));
    }
    for part in split_keys(&raw) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let path = expand_tilde(part);
        let path_buf = PathBuf::from(&path);
        if path_buf.exists() {
            let content = fs::read_to_string(&path_buf)
                .with_context(|| format!("Failed to read ssh key: {}", path_buf.display()))?;
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    keys.push(line.to_string());
                }
            }
        } else {
            keys.push(part.to_string());
        }
    }

    Ok(dedupe_keys(keys))
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

fn split_keys(value: &str) -> Vec<&str> {
    value
        .split(|ch| ch == '\n' || ch == ',' || ch == ';')
        .collect()
}

fn looks_like_ssh_key(value: &str) -> bool {
    let mut parts = value.split_whitespace();
    let key_type = match parts.next() {
        Some(key_type) => key_type,
        None => return false,
    };
    let key_body = match parts.next() {
        Some(key_body) => key_body,
        None => return false,
    };
    if key_body.is_empty() {
        return false;
    }
    key_type.starts_with("ssh-") || key_type.starts_with("ecdsa-") || key_type.starts_with("sk-")
}

fn dedupe_keys(keys: Vec<String>) -> Option<String> {
    if keys.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for key in keys {
        if seen.insert(key.clone()) {
            deduped.push(key);
        }
    }
    Some(deduped.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_latest_image_prefers_newest() {
        let images = vec![
            ImageSummary {
                id: "old".to_string(),
                display_name: "old".to_string(),
                operating_system: None,
                operating_system_version: None,
                time_created: Some("2023-01-01T00:00:00Z".to_string()),
            },
            ImageSummary {
                id: "new".to_string(),
                display_name: "new".to_string(),
                operating_system: None,
                operating_system_version: None,
                time_created: Some("2024-01-01T00:00:00Z".to_string()),
            },
        ];
        let selected = select_latest_image(images).expect("select");
        assert_eq!(selected, "new");
    }

    #[test]
    fn resolve_ssh_key_returns_inline_if_missing() {
        let result = resolve_ssh_key(Some("ssh-rsa AAAA".to_string()), true).expect("ssh");
        assert_eq!(result, Some("ssh-rsa AAAA".to_string()));
    }

    #[test]
    fn resolve_ssh_key_inline_only_accepts_key() {
        let result =
            resolve_ssh_key(Some("ssh-ed25519 AAAA comment".to_string()), false).expect("ssh");
        assert_eq!(result, Some("ssh-ed25519 AAAA comment".to_string()));
    }

    #[test]
    fn resolve_ssh_key_inline_only_rejects_path() {
        let result = resolve_ssh_key(Some("C:\\\\keys\\\\id_rsa.pub".to_string()), false);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_ssh_key_dedup_removes_duplicates() {
        let input = "ssh-rsa AAAA\nssh-rsa AAAA\nssh-ed25519 BBBB".to_string();
        let result = resolve_ssh_key(Some(input), true).expect("ssh");
        assert_eq!(result, Some("ssh-rsa AAAA\nssh-ed25519 BBBB".to_string()));
    }

    #[test]
    fn resolve_ssh_key_none_returns_none() {
        let result = resolve_ssh_key(None, true).expect("ssh");
        assert_eq!(result, None);
    }

    #[test]
    fn select_latest_image_empty_list_errors() {
        let result = select_latest_image(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn looks_like_ssh_key_validates_correctly() {
        assert!(looks_like_ssh_key("ssh-rsa AAAA"));
        assert!(looks_like_ssh_key("ssh-ed25519 AAAA comment"));
        assert!(looks_like_ssh_key("ecdsa-sha2-nistp256 AAAA"));
        assert!(!looks_like_ssh_key(""));
        assert!(!looks_like_ssh_key("justoneword"));
        assert!(!looks_like_ssh_key("C:\\keys\\id_rsa.pub"));
    }

    #[test]
    fn split_keys_handles_separators() {
        let result = split_keys("key1\nkey2,key3;key4");
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn dedupe_keys_empty_returns_none() {
        assert_eq!(dedupe_keys(vec![]), None);
    }
}
