use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceSummary {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: String,
    #[serde(rename = "availabilityDomain")]
    pub availability_domain: String,
    pub shape: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityDomain {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shape {
    pub shape: String,
    #[serde(rename = "ocpus")]
    pub ocpus: Option<f64>,
    #[serde(rename = "memoryInGBs")]
    pub memory_in_gbs: Option<f64>,
    #[serde(rename = "ocpuOptions")]
    pub ocpu_options: Option<ShapeOcpuOptions>,
    #[serde(rename = "memoryOptions")]
    pub memory_options: Option<ShapeMemoryOptions>,
    #[serde(rename = "processorDescription")]
    pub processor_description: Option<String>,
    #[serde(rename = "isFlexible")]
    pub is_flexible: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapeOcpuOptions {
    pub min: Option<f64>,
    pub max: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapeMemoryOptions {
    #[serde(rename = "minInGBs")]
    pub min_in_gbs: Option<f64>,
    #[serde(rename = "maxInGBs")]
    pub max_in_gbs: Option<f64>,
    #[serde(rename = "minPerOcpuInGBs")]
    pub min_per_ocpu_in_gbs: Option<f64>,
    #[serde(rename = "maxPerOcpuInGBs")]
    pub max_per_ocpu_in_gbs: Option<f64>,
    #[serde(rename = "defaultPerOcpuInGBs")]
    pub default_per_ocpu_in_gbs: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSummary {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "operatingSystem")]
    pub operating_system: Option<String>,
    #[serde(rename = "operatingSystemVersion")]
    pub operating_system_version: Option<String>,
    #[serde(rename = "timeCreated")]
    pub time_created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetSummary {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "cidrBlock")]
    pub cidr_block: Option<String>,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: Option<String>,
    #[serde(rename = "vcnId")]
    pub vcn_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompartmentSummary {
    pub id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "description")]
    pub description: Option<String>,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: Option<String>,
}
