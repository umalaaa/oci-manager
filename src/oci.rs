use std::fs;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use pkcs8::DecodePrivateKey;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, DATE, HOST,
};
use reqwest::Method;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;
use url::Url;

use crate::config::Profile;
use crate::models::{
    AvailabilityDomain, CompartmentSummary, ImageSummary, InstanceSummary, Shape, SubnetSummary,
};

#[derive(Debug, Clone, Copy)]
pub enum Service {
    Compute,
    Identity,
    VirtualNetwork,
}

pub struct OciClient {
    pub profile: Profile,
    http: reqwest::Client,
    signer: Signer,
}

impl OciClient {
    pub fn new(profile: Profile) -> Result<Self> {
        let signer = Signer::new(&profile)?;
        let http = reqwest::Client::builder().build()?;
        Ok(Self {
            profile,
            http,
            signer,
        })
    }

    pub async fn list_instances(&self, compartment_id: &str) -> Result<Vec<InstanceSummary>> {
        let query = vec![("compartmentId".to_string(), compartment_id.to_string())];
        self.request_json(
            Service::Compute,
            Method::GET,
            "/20160918/instances",
            query,
            None,
        )
        .await
    }

    pub async fn terminate_instance(&self, instance_id: &str) -> Result<()> {
        let path = format!("/20160918/instances/{}", instance_id);
        self.request_empty(Service::Compute, Method::DELETE, &path, vec![], None)
            .await
    }

    pub async fn reboot_instance(&self, instance_id: &str, hard: bool) -> Result<()> {
        let action = if hard { "RESET" } else { "SOFTRESET" };
        let path = format!("/20160918/instances/{}?action={}", instance_id, action);
        self.request_empty(Service::Compute, Method::POST, &path, vec![], None)
            .await
    }

    pub async fn availability_domains(
        &self,
        compartment_id: &str,
    ) -> Result<Vec<AvailabilityDomain>> {
        let query = vec![("compartmentId".to_string(), compartment_id.to_string())];
        self.request_json(
            Service::Identity,
            Method::GET,
            "/20160918/availabilityDomains",
            query,
            None,
        )
        .await
    }

    pub async fn list_shapes(
        &self,
        compartment_id: &str,
        availability_domain: &str,
    ) -> Result<Vec<Shape>> {
        let query = vec![
            ("compartmentId".to_string(), compartment_id.to_string()),
            (
                "availabilityDomain".to_string(),
                availability_domain.to_string(),
            ),
        ];
        self.request_json(
            Service::Compute,
            Method::GET,
            "/20160918/shapes",
            query,
            None,
        )
        .await
    }

    pub async fn list_images(
        &self,
        compartment_id: &str,
        shape: &str,
        os: Option<&str>,
        os_version: Option<&str>,
    ) -> Result<Vec<ImageSummary>> {
        let mut query = vec![
            ("compartmentId".to_string(), compartment_id.to_string()),
            ("shape".to_string(), shape.to_string()),
        ];
        if let Some(os) = os {
            query.push(("operatingSystem".to_string(), os.to_string()));
        }
        if let Some(version) = os_version {
            query.push(("operatingSystemVersion".to_string(), version.to_string()));
        }
        self.request_json(
            Service::Compute,
            Method::GET,
            "/20160918/images",
            query,
            None,
        )
        .await
    }

    pub async fn list_subnets(&self, compartment_id: &str) -> Result<Vec<SubnetSummary>> {
        let query = vec![("compartmentId".to_string(), compartment_id.to_string())];
        self.request_json(
            Service::VirtualNetwork,
            Method::GET,
            "/20160918/subnets",
            query,
            None,
        )
        .await
    }

    pub async fn list_compartments(&self) -> Result<Vec<CompartmentSummary>> {
        let query = vec![
            ("compartmentId".to_string(), self.profile.tenancy.clone()),
            ("accessLevel".to_string(), "ACCESSIBLE".to_string()),
            ("compartmentIdInSubtree".to_string(), "true".to_string()),
        ];
        self.request_json(
            Service::Identity,
            Method::GET,
            "/20160918/compartments",
            query,
            None,
        )
        .await
    }

    pub fn tenancy(&self) -> &str {
        &self.profile.tenancy
    }

    pub async fn create_instance(&self, payload: serde_json::Value) -> Result<InstanceSummary> {
        self.request_json(
            Service::Compute,
            Method::POST,
            "/20160918/instances",
            vec![],
            Some(payload),
        )
        .await
    }

    async fn request_json<T: serde::de::DeserializeOwned>(
        &self,
        service: Service,
        method: Method,
        path: &str,
        mut query: Vec<(String, String)>,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let (url, host, path_and_query) = self
            .build_url(service, path, &mut query)
            .context("build url")?;

        let mut body_bytes = match body {
            Some(value) => Some(serde_json::to_vec(&value)?),
            None => None,
        };
        if body_bytes.is_none() && requires_body_headers(&method) {
            body_bytes = Some(Vec::new());
        }

        let headers =
            self.signer
                .signed_headers(&method, &host, &path_and_query, body_bytes.as_deref())?;

        let mut request = self.http.request(method, url);
        for (name, value) in headers.iter() {
            request = request.header(name, value);
        }
        if let Some(bytes) = body_bytes {
            request = request.body(bytes);
        }

        let response = request.send().await?;
        Self::handle_response(response).await
    }

    async fn request_empty(
        &self,
        service: Service,
        method: Method,
        path: &str,
        mut query: Vec<(String, String)>,
        body: Option<serde_json::Value>,
    ) -> Result<()> {
        let (url, host, path_and_query) = self
            .build_url(service, path, &mut query)
            .context("build url")?;

        let mut body_bytes = match body {
            Some(value) => Some(serde_json::to_vec(&value)?),
            None => None,
        };
        if body_bytes.is_none() && requires_body_headers(&method) {
            body_bytes = Some(Vec::new());
        }

        let headers =
            self.signer
                .signed_headers(&method, &host, &path_and_query, body_bytes.as_deref())?;

        let mut request = self.http.request(method, url);
        for (name, value) in headers.iter() {
            request = request.header(name, value);
        }
        if let Some(bytes) = body_bytes {
            request = request.body(bytes);
        }

        let response = request.send().await?;
        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("OCI error {}: {}", status, body)
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T> {
        if response.status().is_success() {
            return Ok(response.json::<T>().await?);
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("OCI error {}: {}", status, body)
    }

    fn build_url(
        &self,
        service: Service,
        path: &str,
        query: &mut [(String, String)],
    ) -> Result<(Url, String, String)> {
        let base = match service {
            Service::Compute | Service::VirtualNetwork => {
                format!("https://iaas.{}.oraclecloud.com", self.profile.region)
            }
            Service::Identity => {
                format!("https://identity.{}.oraclecloud.com", self.profile.region)
            }
        };
        query.sort_by(|a, b| a.0.cmp(&b.0));
        let query_string = build_query_string(query);
        let path_and_query = if query_string.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, query_string)
        };
        let url = Url::parse(&format!("{}{}", base, path_and_query))?;
        let host = url
            .host_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("Missing host in url"))?;
        Ok((url, host, path_and_query))
    }
}

struct Signer {
    key_id: String,
    key: RsaPrivateKey,
}

impl Signer {
    fn new(profile: &Profile) -> Result<Self> {
        if !profile.key_file.exists() {
            bail!("Private key file not found: {}", profile.key_file.display());
        }
        let raw_pem = fs::read_to_string(&profile.key_file)
            .with_context(|| format!("Failed to read key file: {}", profile.key_file.display()))?;
        let pem = extract_pem_block(&raw_pem).unwrap_or(raw_pem);
        let key = RsaPrivateKey::from_pkcs8_pem(&pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
            .context("Failed to parse private key (PKCS#8 or PKCS#1)")?;
        let key_id = format!(
            "{}/{}/{}",
            profile.tenancy, profile.user, profile.fingerprint
        );
        Ok(Self { key_id, key })
    }

    fn signed_headers(
        &self,
        method: &Method,
        host: &str,
        path_and_query: &str,
        body: Option<&[u8]>,
    ) -> Result<HeaderMap> {
        let date = OffsetDateTime::now_utc()
            .format(&Rfc2822)?
            .replace("+0000", "GMT");
        let request_target = format!("{} {}", method.as_str().to_lowercase(), path_and_query);

        let mut header_items = Vec::new();
        header_items.push(("date", date.clone()));
        header_items.push(("(request-target)", request_target));
        header_items.push(("host", host.to_string()));

        let mut headers = HeaderMap::new();
        headers.insert(DATE, HeaderValue::from_str(&date)?);
        headers.insert(HOST, HeaderValue::from_str(host)?);

        if let Some(body) = body {
            let content_length = body.len().to_string();
            let content_type = "application/json".to_string();
            let mut hasher = Sha256::new();
            hasher.update(body);
            let digest = hasher.finalize();
            let content_hash = BASE64.encode(digest);

            headers.insert(CONTENT_LENGTH, HeaderValue::from_str(&content_length)?);
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(&content_type)?);
            headers.insert(
                HeaderName::from_static("x-content-sha256"),
                HeaderValue::from_str(&content_hash)?,
            );

            header_items.push(("content-length", content_length));
            header_items.push(("content-type", content_type));
            header_items.push(("x-content-sha256", content_hash));
        }

        let signing_string = build_signing_string(&header_items);
        let signature = self.sign(&signing_string)?;
        let signed_headers = header_items
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(" ");

        let auth_header = format!(
            "Signature version=\"1\",keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"",
            self.key_id, signed_headers, signature
        );
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_header)?);

        Ok(headers)
    }

    fn sign(&self, signing_string: &str) -> Result<String> {
        let padding = Pkcs1v15Sign::new::<Sha256>();
        let mut hasher = Sha256::new();
        hasher.update(signing_string.as_bytes());
        let digest = hasher.finalize();
        let signature = self
            .key
            .sign(padding, &digest)
            .context("Failed to sign request")?;
        Ok(BASE64.encode(signature))
    }
}

fn build_signing_string(items: &[(impl AsRef<str>, impl AsRef<str>)]) -> String {
    let mut result = String::new();
    for (idx, (name, value)) in items.iter().enumerate() {
        if idx > 0 {
            result.push('\n');
        }
        result.push_str(name.as_ref());
        result.push_str(": ");
        result.push_str(value.as_ref());
    }
    result
}

fn build_query_string(query: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in query {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

/// Extract the PEM block from raw file content.
/// OCI key downloads sometimes include trailing text (e.g. "OCI_API_KEY")
/// after the END marker which breaks PEM parsers.
fn extract_pem_block(raw: &str) -> Option<String> {
    let start = raw.find("-----BEGIN ")?;
    let end_marker = "-----END ";
    let end_start = raw.find(end_marker)?;
    let end_line_end = raw[end_start..]
        .find("-----\n")
        .or_else(|| raw[end_start..].find("-----\r\n"))
        .or_else(|| {
            // handle case where END marker is at very end of file with no newline
            if raw[end_start..].ends_with("-----") {
                Some(raw[end_start..].len() - 5)
            } else {
                None
            }
        })?;
    let end = end_start + end_line_end + 5; // include the trailing "-----"
    Some(raw[start..end].trim().to_string())
}

fn requires_body_headers(method: &Method) -> bool {
    matches!(method, &Method::POST | &Method::PUT | &Method::DELETE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;

    #[test]
    fn signing_string_format() {
        let items = vec![
            ("date", "Tue, 10 Feb 2026 00:00:00 GMT"),
            ("(request-target)", "get /20160918/instances"),
            ("host", "iaas.us-phoenix-1.oraclecloud.com"),
        ];
        let result = build_signing_string(&items);
        assert!(result.contains("date: Tue, 10 Feb 2026"));
        assert!(result.contains("(request-target): get /20160918/instances"));
        assert!(result.contains("host: iaas.us-phoenix-1.oraclecloud.com"));
    }

    #[test]
    fn sign_with_generated_key() {
        let mut rng = OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("key");
        let signer = Signer {
            key_id: "tenancy/user/fingerprint".to_string(),
            key,
        };
        let signature = signer.sign("date: Tue").expect("sign");
        assert!(!signature.is_empty());
    }
}
