use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum NvdError {
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Failed to parse JSON: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("SBOM parse error: {0}")]
    SbomError(String),

    #[error("Database error: {0}")]
    DbError(String),
}

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser)]
#[command(name = "nvd-cve-client")]
#[command(about = "Query NVD for CVEs and check SBOMs for vulnerabilities")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sync CVE database from NVD (downloads recent CVEs)
    Sync {
        /// Number of days to sync (default: 7, max: 120)
        #[arg(short, long, default_value = "7")]
        days: u32,

        /// Force full re-sync (ignore existing data)
        #[arg(short, long)]
        force: bool,

        /// Skip CISA KEV catalog sync
        #[arg(long)]
        no_kev: bool,
    },

    /// Scan an SBOM against the local CVE database (fast, no API calls)
    Scan {
        /// Path to the SBOM file (CycloneDX or SPDX JSON format)
        #[arg(short, long)]
        sbom: PathBuf,

        /// Only show vulnerabilities with CVSS score >= this value
        #[arg(short = 'm', long, default_value = "0.0")]
        min_severity: f64,

        /// Output format: text, json, or markdown
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Save scan results to file
        #[arg(short = 'f', long)]
        output_file: Option<PathBuf>,

        /// Path to a manually downloaded CISA KEV catalog JSON file
        #[arg(long)]
        kev_file: Option<PathBuf>,
    },

    /// Analyze vulnerabilities with AI for prioritization and remediation
    Analyze {
        /// Path to the SBOM file (CycloneDX or SPDX JSON format)
        #[arg(short, long)]
        sbom: PathBuf,

        /// Only analyze vulnerabilities with CVSS score >= this value
        #[arg(short = 'm', long, default_value = "7.0")]
        min_severity: f64,

        /// Output format: text, json, or markdown
        #[arg(short, long, default_value = "markdown")]
        output: String,

        /// Save analysis to file
        #[arg(short = 'f', long)]
        output_file: Option<PathBuf>,

        /// Path to a manually downloaded CISA KEV catalog JSON file
        #[arg(long)]
        kev_file: Option<PathBuf>,

        /// AI provider to use for analysis
        #[arg(long, value_enum)]
        ai_provider: Option<AiProvider>,

        /// Override the model name for the selected provider
        #[arg(long)]
        ai_model: Option<String>,

        /// Reasoning effort (OpenAI only)
        #[arg(long, value_enum)]
        reasoning_effort: Option<ReasoningEffort>,
    },

    /// Show database statistics
    Stats,

    /// Look up a specific CVE by ID (searches local DB first, then API)
    Lookup {
        /// CVE ID (e.g., CVE-2024-1234)
        cve_id: String,

        /// Path to a manually downloaded CISA KEV catalog JSON file
        #[arg(long)]
        kev_file: Option<PathBuf>,
    },

    /// Fetch recent CVEs from NVD API (does not save to DB)
    Recent {
        /// Number of days to look back
        #[arg(short, long, default_value = "7")]
        days: u32,

        /// Maximum number of results to display
        #[arg(short, long, default_value = "100")]
        limit: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AiProvider {
    Claude,
    Openai,
}

impl AiProvider {
    fn as_str(&self) -> &'static str {
        match self {
            AiProvider::Claude => "claude",
            AiProvider::Openai => "openai",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
}

impl ReasoningEffort {
    fn as_str(&self) -> &'static str {
        match self {
            ReasoningEffort::None => "none",
            ReasoningEffort::Minimal => "minimal",
            ReasoningEffort::Low => "low",
            ReasoningEffort::Medium => "medium",
            ReasoningEffort::High => "high",
            ReasoningEffort::Xhigh => "xhigh",
        }
    }
}

// ============================================================================
// NVD API Response Types
// ============================================================================

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveResponse {
    pub results_per_page: u32,
    pub start_index: u32,
    pub total_results: u32,
    pub format: String,
    pub version: String,
    pub timestamp: String,
    #[serde(default)]
    pub vulnerabilities: Vec<VulnerabilityWrapper>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VulnerabilityWrapper {
    pub cve: Cve,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    pub id: String,
    pub source_identifier: Option<String>,
    pub published: String,
    pub last_modified: String,
    pub vuln_status: Option<String>,
    #[serde(default)]
    pub descriptions: Vec<Description>,
    #[serde(default)]
    pub metrics: Option<Metrics>,
    #[serde(default)]
    pub weaknesses: Vec<Weakness>,
    #[serde(default)]
    pub configurations: Vec<Configuration>,
    #[serde(default)]
    pub references: Vec<Reference>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    #[serde(default)]
    pub cvss_metric_v31: Vec<CvssMetricV3>,
    #[serde(default)]
    pub cvss_metric_v30: Vec<CvssMetricV3>,
    #[serde(default)]
    pub cvss_metric_v2: Vec<CvssMetricV2>,
    #[serde(default)]
    pub cvss_metric_v40: Vec<CvssMetricV4>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV3 {
    pub source: String,
    #[serde(rename = "type")]
    pub metric_type: String,
    pub cvss_data: CvssV3Data,
    pub exploitability_score: Option<f64>,
    pub impact_score: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssV3Data {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub base_severity: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV2 {
    pub source: String,
    #[serde(rename = "type")]
    pub metric_type: String,
    pub cvss_data: CvssV2Data,
    pub base_severity: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2Data {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV4 {
    pub source: String,
    #[serde(rename = "type")]
    pub metric_type: String,
    pub cvss_data: CvssV4Data,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CvssV4Data {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub base_severity: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Weakness {
    pub source: String,
    #[serde(rename = "type")]
    pub weakness_type: String,
    #[serde(default)]
    pub description: Vec<Description>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Configuration {
    #[serde(default)]
    pub nodes: Vec<Node>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub operator: Option<String>,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
    pub match_criteria_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Reference {
    pub url: String,
    pub source: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

// ============================================================================
// CISA KEV (Known Exploited Vulnerabilities) Types
// ============================================================================

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Raw CISA KEV JSON response structure
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KevResponse {
    pub title: String,
    pub catalog_version: String,
    pub date_released: String,
    pub count: usize,
    pub vulnerabilities: Vec<KevVulnerability>,
}

/// A single KEV entry from CISA
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KevVulnerability {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    pub known_ransomware_campaign_use: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub cwes: Vec<String>,
}

/// Local KEV catalog (parallels CveDatabase pattern)
#[derive(Debug, Serialize, Deserialize)]
pub struct KevCatalog {
    pub last_sync: String,
    pub catalog_version: String,
    pub date_released: String,
    pub kev_count: usize,
    pub vulnerabilities: HashMap<String, KevVulnerability>,
}

impl KevCatalog {
    pub fn new() -> Self {
        Self {
            last_sync: Utc::now().to_rfc3339(),
            catalog_version: String::new(),
            date_released: String::new(),
            kev_count: 0,
            vulnerabilities: HashMap::new(),
        }
    }

    pub fn get_db_path() -> Result<PathBuf, NvdError> {
        if let Some(proj_dirs) = ProjectDirs::from("com", "nvd", "nvd-cve-scanner") {
            let data_dir = proj_dirs.data_dir();
            std::fs::create_dir_all(data_dir)?;
            Ok(data_dir.join("kev_catalog.json"))
        } else {
            Ok(PathBuf::from("kev_catalog.json"))
        }
    }

    pub fn load() -> Result<Self, NvdError> {
        let path = Self::get_db_path()?;
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let catalog: KevCatalog = serde_json::from_str(&content)?;
            Ok(catalog)
        } else {
            Ok(Self::new())
        }
    }

    pub fn save(&self) -> Result<(), NvdError> {
        let path = Self::get_db_path()?;
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    pub fn contains(&self, cve_id: &str) -> bool {
        self.vulnerabilities.contains_key(cve_id)
    }

    pub fn get(&self, cve_id: &str) -> Option<&KevVulnerability> {
        self.vulnerabilities.get(cve_id)
    }

    pub fn update_from_response(&mut self, response: KevResponse) {
        self.catalog_version = response.catalog_version;
        self.date_released = response.date_released;
        self.vulnerabilities.clear();
        for vuln in response.vulnerabilities {
            self.vulnerabilities.insert(vuln.cve_id.clone(), vuln);
        }
        self.kev_count = self.vulnerabilities.len();
        self.last_sync = Utc::now().to_rfc3339();
    }

    pub fn ransomware_count(&self) -> usize {
        self.vulnerabilities
            .values()
            .filter(|v| v.known_ransomware_campaign_use == "Known")
            .count()
    }

    pub fn overdue_count(&self) -> usize {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        self.vulnerabilities
            .values()
            .filter(|v| v.due_date < today)
            .count()
    }

    /// Load KEV from a user-provided file
    pub fn load_from_file(path: &PathBuf) -> Result<Self, NvdError> {
        let content = std::fs::read_to_string(path).map_err(|e| NvdError::IoError(e))?;
        let response: KevResponse = serde_json::from_str(&content)
            .map_err(|e| NvdError::SbomError(format!("Failed to parse KEV file: {}", e)))?;
        let mut catalog = Self::new();
        catalog.update_from_response(response);
        Ok(catalog)
    }
}

// ============================================================================
// Local CVE Database
// ============================================================================

const MAX_DB_SIZE_BYTES: u64 = 500 * 1024 * 1024; // 500MB limit

#[derive(Debug, Serialize, Deserialize)]
pub struct CveDatabase {
    pub last_sync: String,
    pub sync_days: u32,
    pub cve_count: usize,
    pub cves: HashMap<String, Cve>,
}

impl CveDatabase {
    pub fn new() -> Self {
        Self {
            last_sync: Utc::now().to_rfc3339(),
            sync_days: 0,
            cve_count: 0,
            cves: HashMap::new(),
        }
    }

    pub fn get_db_path() -> Result<PathBuf, NvdError> {
        if let Some(proj_dirs) = ProjectDirs::from("com", "nvd", "nvd-cve-scanner") {
            let data_dir = proj_dirs.data_dir();
            std::fs::create_dir_all(data_dir)?;
            Ok(data_dir.join("cve_database.json"))
        } else {
            // Fallback to current directory
            Ok(PathBuf::from("cve_database.json"))
        }
    }

    pub fn load() -> Result<Self, NvdError> {
        let path = Self::get_db_path()?;
        if path.exists() {
            // Check file size before loading
            let metadata = std::fs::metadata(&path)?;
            if metadata.len() > MAX_DB_SIZE_BYTES {
                return Err(NvdError::DbError(format!(
                    "Database file too large ({} bytes). Consider running sync with fewer days.",
                    metadata.len()
                )));
            }

            let content = std::fs::read_to_string(&path)?;
            let db: CveDatabase = serde_json::from_str(&content)?;
            Ok(db)
        } else {
            Ok(Self::new())
        }
    }

    pub fn save(&self) -> Result<(), NvdError> {
        let path = Self::get_db_path()?;
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    pub fn add_cves(&mut self, cves: Vec<Cve>) {
        for cve in cves {
            self.cves.insert(cve.id.clone(), cve);
        }
        self.cve_count = self.cves.len();
        self.last_sync = Utc::now().to_rfc3339();
    }

    pub fn get(&self, cve_id: &str) -> Option<&Cve> {
        self.cves.get(cve_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Cve> {
        self.cves.values()
    }
}

// ============================================================================
// SBOM Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct SbomComponent {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub vendor: Option<String>,
    pub component_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxSbom {
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: Option<String>,
    name: String,
    version: Option<String>,
    purl: Option<String>,
    cpe: Option<String>,
    publisher: Option<String>,
    group: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxSbom {
    #[serde(default)]
    packages: Vec<SpdxPackage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    name: String,
    version_info: Option<String>,
    #[serde(default)]
    external_refs: Vec<SpdxExternalRef>,
    supplier: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_type: Option<String>,
    reference_locator: Option<String>,
}

// ============================================================================
// SBOM Parser
// ============================================================================

const MAX_SBOM_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100MB limit

pub fn parse_sbom(path: &PathBuf) -> Result<Vec<SbomComponent>, NvdError> {
    // Check file size to prevent memory exhaustion
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_SBOM_SIZE_BYTES {
        return Err(NvdError::SbomError(format!(
            "SBOM file too large ({} bytes). Maximum allowed: {} bytes",
            metadata.len(),
            MAX_SBOM_SIZE_BYTES
        )));
    }

    let content = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    if json.get("bomFormat").is_some() || json.get("components").is_some() {
        parse_cyclonedx(&content)
    } else if json.get("spdxVersion").is_some() || json.get("packages").is_some() {
        parse_spdx(&content)
    } else {
        Err(NvdError::SbomError(
            "Unknown SBOM format. Supported: CycloneDX, SPDX (JSON)".to_string(),
        ))
    }
}

fn parse_cyclonedx(content: &str) -> Result<Vec<SbomComponent>, NvdError> {
    let sbom: CycloneDxSbom = serde_json::from_str(content)?;

    let components = sbom
        .components
        .into_iter()
        .map(|c| SbomComponent {
            name: c.name,
            version: c.version,
            purl: c.purl,
            cpe: c.cpe,
            vendor: c.publisher.or(c.group),
            component_type: c.component_type,
        })
        .collect();

    Ok(components)
}

fn parse_spdx(content: &str) -> Result<Vec<SbomComponent>, NvdError> {
    let sbom: SpdxSbom = serde_json::from_str(content)?;

    let components = sbom
        .packages
        .into_iter()
        .map(|p| {
            let mut purl = None;
            let mut cpe = None;

            for ext_ref in &p.external_refs {
                match ext_ref.reference_type.as_deref() {
                    Some("purl") => purl = ext_ref.reference_locator.clone(),
                    Some("cpe23Type") | Some("cpe22Type") => {
                        cpe = ext_ref.reference_locator.clone()
                    }
                    _ => {}
                }
            }

            SbomComponent {
                name: p.name,
                version: p.version_info,
                purl,
                cpe,
                vendor: p.supplier,
                component_type: None,
            }
        })
        .collect();

    Ok(components)
}

// ============================================================================
// PURL Parser
// ============================================================================

use std::sync::OnceLock;

static PURL_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_purl_regex() -> &'static Regex {
    PURL_REGEX.get_or_init(|| {
        Regex::new(r"pkg:([^/]+)/(?:([^/]+)/)?([^@]+)(?:@(.+))?").expect("Invalid PURL regex")
    })
}

fn parse_purl(purl: &str) -> Option<(String, String, Option<String>)> {
    let re = get_purl_regex();
    let caps = re.captures(purl)?;

    let pkg_type = caps.get(1)?.as_str();
    let namespace = caps.get(2).map(|m| m.as_str());
    let name = caps.get(3)?.as_str();
    let version = caps.get(4).map(|m| m.as_str().to_string());

    let vendor = namespace
        .map(|n| n.trim_start_matches("%40").to_string())
        .unwrap_or_else(|| pkg_type.to_string());

    let clean_name = name.replace("%40", "@").replace("%2F", "/");

    Some((vendor, clean_name, version))
}

// ============================================================================
// NVD Client
// ============================================================================

const REQUEST_TIMEOUT_SECS: u64 = 30;
const MAX_RETRIES: u32 = 3;

pub struct NvdClient {
    client: Client,
    api_key: Option<String>,
    base_url: String,
}

impl NvdClient {
    pub fn new(api_key: Option<String>) -> Self {
        // Build client with security best practices
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            api_key,
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
        }
    }

    fn rate_limit_delay(&self) -> u64 {
        if self.api_key.is_some() {
            1
        } else {
            6
        }
    }

    fn format_datetime(dt: DateTime<Utc>) -> String {
        dt.format("%Y-%m-%dT%H:%M:%S%.3f").to_string()
    }

    pub async fn get_cve_by_id(&self, cve_id: &str) -> Result<CveResponse, NvdError> {
        let params = vec![("cveId", cve_id.to_string())];
        self.fetch_cves(params).await
    }

    pub async fn get_cves_by_pub_date(
        &self,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
        start_index: u32,
        results_per_page: Option<u32>,
    ) -> Result<CveResponse, NvdError> {
        let mut params = vec![
            ("pubStartDate", Self::format_datetime(start_date)),
            ("pubEndDate", Self::format_datetime(end_date)),
            ("startIndex", start_index.to_string()),
        ];

        if let Some(rpp) = results_per_page {
            params.push(("resultsPerPage", rpp.to_string()));
        }

        self.fetch_cves(params).await
    }

    pub async fn get_cves_by_mod_date(
        &self,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
        start_index: u32,
        results_per_page: Option<u32>,
    ) -> Result<CveResponse, NvdError> {
        let mut params = vec![
            ("lastModStartDate", Self::format_datetime(start_date)),
            ("lastModEndDate", Self::format_datetime(end_date)),
            ("startIndex", start_index.to_string()),
        ];

        if let Some(rpp) = results_per_page {
            params.push(("resultsPerPage", rpp.to_string()));
        }

        self.fetch_cves(params).await
    }

    /// Sync all CVEs from the last N days with pagination
    pub async fn sync_cves(&self, days: u32) -> Result<Vec<Cve>, NvdError> {
        let end_date = Utc::now();
        let start_date = end_date - Duration::days(days as i64);

        let mut all_cves = Vec::new();
        let mut start_index = 0u32;
        let results_per_page = 2000u32;

        println!(
            "Syncing CVEs from {} to {}",
            start_date.format("%Y-%m-%d"),
            end_date.format("%Y-%m-%d")
        );

        loop {
            println!("  Fetching from index {}...", start_index);

            let response = self
                .get_cves_by_mod_date(start_date, end_date, start_index, Some(results_per_page))
                .await?;

            let fetched_count = response.vulnerabilities.len() as u32;
            println!(
                "    Got {} CVEs (total available: {})",
                fetched_count, response.total_results
            );

            for vuln in response.vulnerabilities {
                all_cves.push(vuln.cve);
            }

            if start_index + fetched_count >= response.total_results {
                break;
            }

            start_index += results_per_page;
            tokio::time::sleep(tokio::time::Duration::from_secs(self.rate_limit_delay())).await;
        }

        Ok(all_cves)
    }

    async fn fetch_cves(&self, params: Vec<(&str, String)>) -> Result<CveResponse, NvdError> {
        let mut last_error = None;

        for attempt in 1..=MAX_RETRIES {
            let request = self.client.get(&self.base_url).query(&params);

            let request = if let Some(ref api_key) = self.api_key {
                request.header("apiKey", api_key)
            } else {
                request
            };

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return response.json().await.map_err(NvdError::from);
                    } else if response.status().is_server_error() && attempt < MAX_RETRIES {
                        // Retry on 5xx errors
                        let delay = std::time::Duration::from_secs(2u64.pow(attempt));
                        eprintln!(
                            "Server error ({}), retrying in {:?}... (attempt {}/{})",
                            response.status(),
                            delay,
                            attempt,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(delay).await;
                        last_error = Some(NvdError::ApiError(format!(
                            "API returned status: {}",
                            response.status()
                        )));
                        continue;
                    } else {
                        return Err(NvdError::ApiError(format!(
                            "API returned status: {}",
                            response.status()
                        )));
                    }
                }
                Err(e) if attempt < MAX_RETRIES => {
                    // Retry on connection errors
                    let delay = std::time::Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "Request failed: {}, retrying in {:?}... (attempt {}/{})",
                        e, delay, attempt, MAX_RETRIES
                    );
                    tokio::time::sleep(delay).await;
                    last_error = Some(NvdError::from(e));
                    continue;
                }
                Err(e) => return Err(NvdError::from(e)),
            }
        }

        Err(last_error.unwrap_or_else(|| NvdError::ApiError("Max retries exceeded".to_string())))
    }

    /// Fetch the CISA Known Exploited Vulnerabilities catalog
    pub async fn fetch_kev_catalog(&self) -> Result<KevResponse, NvdError> {
        println!("Fetching CISA KEV catalog...");

        let mut last_error = None;

        for attempt in 1..=MAX_RETRIES {
            match self.client.get(KEV_URL).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        let kev: KevResponse = response.json().await?;
                        println!(
                            "  Retrieved {} KEV entries (catalog version: {})",
                            kev.count, kev.catalog_version
                        );
                        return Ok(kev);
                    } else if response.status().is_server_error() && attempt < MAX_RETRIES {
                        let delay = std::time::Duration::from_secs(2u64.pow(attempt));
                        eprintln!(
                            "KEV server error ({}), retrying in {:?}... (attempt {}/{})",
                            response.status(),
                            delay,
                            attempt,
                            MAX_RETRIES
                        );
                        tokio::time::sleep(delay).await;
                        last_error = Some(NvdError::ApiError(format!(
                            "KEV API returned status: {}",
                            response.status()
                        )));
                        continue;
                    } else {
                        return Err(NvdError::ApiError(format!(
                            "KEV API returned status: {}",
                            response.status()
                        )));
                    }
                }
                Err(e) if attempt < MAX_RETRIES => {
                    let delay = std::time::Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "KEV request failed: {}, retrying in {:?}... (attempt {}/{})",
                        e, delay, attempt, MAX_RETRIES
                    );
                    tokio::time::sleep(delay).await;
                    last_error = Some(NvdError::from(e));
                    continue;
                }
                Err(e) => return Err(NvdError::from(e)),
            }
        }

        Err(last_error
            .unwrap_or_else(|| NvdError::ApiError("KEV max retries exceeded".to_string())))
    }
}

/// Fetch fresh KEV catalog from CISA, falling back to local cache on failure.
/// If a kev_file path is provided, loads from that file instead.
async fn load_kev_live(client: &NvdClient, kev_file: Option<&PathBuf>) -> Option<KevCatalog> {
    // If user provided a manual KEV file, use it directly
    if let Some(path) = kev_file {
        println!("Loading KEV catalog from: {}", path.display());
        match KevCatalog::load_from_file(path) {
            Ok(catalog) => {
                println!(
                    "KEV catalog loaded: {} entries (version: {})",
                    catalog.kev_count, catalog.catalog_version
                );
                return Some(catalog);
            }
            Err(e) => {
                eprintln!("ERROR: Failed to load KEV file '{}': {}", path.display(), e);
                return None;
            }
        }
    }

    // Try live fetch
    match client.fetch_kev_catalog().await {
        Ok(response) => {
            let mut catalog = KevCatalog::new();
            catalog.update_from_response(response);
            // Cache locally for offline fallback
            if let Err(e) = catalog.save() {
                eprintln!("WARNING: Failed to cache KEV catalog locally: {}", e);
            }
            Some(catalog)
        }
        Err(e) => {
            eprintln!("WARNING: Failed to fetch CISA KEV catalog: {}", e);
            // Try local cache fallback
            match KevCatalog::load() {
                Ok(catalog) if catalog.kev_count > 0 => {
                    eprintln!(
                        "Falling back to cached KEV data ({} entries, last sync: {})",
                        catalog.kev_count, catalog.last_sync
                    );
                    Some(catalog)
                }
                _ => {
                    eprintln!(
                        "WARNING: CISA KEV catalog unavailable (fetch failed, no local cache)."
                    );
                    eprintln!("KEV enrichment will be skipped for this run.");
                    eprintln!(
                        "Tip: You can manually provide a KEV catalog file with --kev-file <path>"
                    );
                    eprintln!("     Download it from: {}", KEV_URL);
                    None
                }
            }
        }
    }
}

// ============================================================================
// AI Analysis Clients (Claude + OpenAI/Codex)
// ============================================================================

const DEFAULT_CLAUDE_MODEL: &str = "claude-sonnet-4-20250514";
const DEFAULT_OPENAI_MODEL: &str = "gpt-5.3-codex";

#[derive(Debug, Clone)]
struct AnalyzeAiConfig {
    provider: AiProvider,
    model: String,
    reasoning_effort: Option<ReasoningEffort>,
}

fn parse_ai_provider(value: &str) -> Option<AiProvider> {
    match value.trim().to_ascii_lowercase().as_str() {
        "claude" | "anthropic" => Some(AiProvider::Claude),
        "openai" | "codex" => Some(AiProvider::Openai),
        _ => None,
    }
}

fn parse_reasoning_effort(value: &str) -> Option<ReasoningEffort> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" => Some(ReasoningEffort::None),
        "minimal" => Some(ReasoningEffort::Minimal),
        "low" => Some(ReasoningEffort::Low),
        "medium" => Some(ReasoningEffort::Medium),
        "high" => Some(ReasoningEffort::High),
        "xhigh" => Some(ReasoningEffort::Xhigh),
        _ => None,
    }
}

fn resolve_ai_config(
    ai_provider: Option<AiProvider>,
    ai_model: Option<String>,
    reasoning_effort: Option<ReasoningEffort>,
) -> Result<AnalyzeAiConfig, NvdError> {
    let provider = if let Some(provider) = ai_provider {
        provider
    } else if let Ok(provider_env) = std::env::var("AI_PROVIDER") {
        parse_ai_provider(&provider_env).ok_or_else(|| {
            NvdError::ApiError(format!(
                "Invalid AI_PROVIDER '{}'. Use 'claude' or 'openai'.",
                provider_env
            ))
        })?
    } else {
        AiProvider::Claude
    };

    let model = if let Some(model) = ai_model {
        model
    } else {
        match provider {
            AiProvider::Claude => std::env::var("ANTHROPIC_MODEL")
                .or_else(|_| std::env::var("CLAUDE_MODEL"))
                .unwrap_or_else(|_| DEFAULT_CLAUDE_MODEL.to_string()),
            AiProvider::Openai => {
                std::env::var("OPENAI_MODEL").unwrap_or_else(|_| DEFAULT_OPENAI_MODEL.to_string())
            }
        }
    };

    let resolved_reasoning = if provider == AiProvider::Openai {
        if let Some(effort) = reasoning_effort {
            Some(effort)
        } else if let Ok(value) = std::env::var("OPENAI_REASONING_EFFORT") {
            Some(parse_reasoning_effort(&value).ok_or_else(|| {
                NvdError::ApiError(format!(
                    "Invalid OPENAI_REASONING_EFFORT '{}'. Use one of: none, minimal, low, medium, high, xhigh.",
                    value
                ))
            })?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(AnalyzeAiConfig {
        provider,
        model,
        reasoning_effort: resolved_reasoning,
    })
}

fn resolve_ai_api_key(provider: AiProvider) -> Result<String, NvdError> {
    match provider {
        AiProvider::Claude => std::env::var("ANTHROPIC_API_KEY")
            .or_else(|_| std::env::var("CLAUDE_API_KEY"))
            .map_err(|_| {
                NvdError::ApiError(
                    "Claude API key not found. Set ANTHROPIC_API_KEY or CLAUDE_API_KEY."
                        .to_string(),
                )
            }),
        AiProvider::Openai => std::env::var("OPENAI_API_KEY").map_err(|_| {
            NvdError::ApiError("OpenAI API key not found. Set OPENAI_API_KEY.".to_string())
        }),
    }
}

fn build_ai_client(config: &AnalyzeAiConfig, api_key: String) -> Result<AiClient, NvdError> {
    Ok(match config.provider {
        AiProvider::Claude => AiClient::Claude(ClaudeClient::new(api_key, config.model.clone())?),
        AiProvider::Openai => AiClient::OpenAi(OpenAiClient::new(
            api_key,
            config.model.clone(),
            config.reasoning_effort,
        )?),
    })
}

enum AiClient {
    Claude(ClaudeClient),
    OpenAi(OpenAiClient),
}

impl AiClient {
    fn provider_name(&self) -> &'static str {
        match self {
            AiClient::Claude(_) => "Claude",
            AiClient::OpenAi(_) => "OpenAI/Codex",
        }
    }

    fn model_name(&self) -> &str {
        match self {
            AiClient::Claude(client) => &client.model,
            AiClient::OpenAi(client) => &client.model,
        }
    }

    async fn analyze_vulnerabilities(
        &self,
        matches: &[VulnerabilityMatch],
        sbom_name: &str,
    ) -> Result<String, NvdError> {
        match self {
            AiClient::Claude(client) => client.analyze_vulnerabilities(matches, sbom_name).await,
            AiClient::OpenAi(client) => client.analyze_vulnerabilities(matches, sbom_name).await,
        }
    }
}

fn build_analysis_prompt(matches: &[VulnerabilityMatch], sbom_name: &str) -> String {
    let vuln_summary = build_vulnerability_summary(matches);
    format!(
        r#"You are a cybersecurity expert analyzing vulnerabilities found in a software bill of materials (SBOM).

## Context
SBOM: {sbom_name}
Total vulnerabilities found: {count}

## Vulnerability Data
{vuln_summary}

## Your Task
Analyze these vulnerabilities and provide a comprehensive security assessment. Be precise and factual - do not speculate or make assumptions beyond what the CVE data shows.

Please provide:

### 1. Executive Summary
A brief overview of the security posture based on these findings.

### 2. Risk-Prioritized Vulnerability List
Rank the vulnerabilities by actual risk considering:
- **CISA KEV status** (vulnerabilities in the CISA Known Exploited Vulnerabilities catalog are confirmed to be actively exploited in the wild and MUST be prioritized above non-KEV entries, per BOD 22-01)
- Ransomware association (KEV entries marked as "Known" ransomware campaign use are highest priority)
- CISA remediation due date urgency
- CVSS score (use the exact scores provided)
- Attack vector (network-accessible vs local)
- Impact on confidentiality, integrity, and availability
- The specific component affected and its role

For each vulnerability, explain WHY you ranked it at that priority level.

### 3. Remediation Guidance
For each vulnerability (in priority order), provide:
- **Immediate action**: What to do right now
- **Fix**: Specific version to upgrade to (if known from CVE data) or mitigation steps
- **Workaround**: If no fix is available, what compensating controls can be applied

### 4. Summary Table
Provide a table with columns: Priority | CVE ID | Component | CVSS | KEV | Recommended Action

### 5. CISA KEV Summary
If any vulnerabilities are in the CISA KEV catalog, provide:
- Total count of KEV entries found
- Which ones have known ransomware campaign associations
- Due dates and whether any are overdue
- Compliance implications (reference BOD 22-01 if applicable)

Be concise but thorough. Focus on actionable guidance."#,
        sbom_name = sbom_name,
        count = matches.len(),
        vuln_summary = vuln_summary
    )
}

fn build_vulnerability_summary(matches: &[VulnerabilityMatch]) -> String {
    let mut summary = String::new();

    for (idx, m) in matches.iter().enumerate() {
        let cve = &m.cve;
        let component = &m.component;

        summary.push_str(&format!("### Vulnerability {}\n", idx + 1));
        summary.push_str(&format!("- **CVE ID**: {}\n", cve.id));
        summary.push_str(&format!(
            "- **Component**: {} {}\n",
            component.name,
            component.version.as_deref().unwrap_or("(unknown version)")
        ));

        if let Some((score, severity)) = cve.highest_cvss_score() {
            summary.push_str(&format!("- **CVSS Score**: {:.1} ({})\n", score, severity));
        }

        let cwes = cve.cwe_ids();
        if !cwes.is_empty() {
            summary.push_str(&format!("- **CWE**: {}\n", cwes.join(", ")));
        }

        summary.push_str(&format!(
            "- **Status**: {}\n",
            cve.vuln_status.as_deref().unwrap_or("N/A")
        ));

        if let Some(desc) = cve.english_description() {
            summary.push_str(&format!("- **Description**: {}\n", desc));
        }

        let affected = cve.affected_products();
        if !affected.is_empty() {
            summary.push_str("- **Affected versions**: ");
            let version_info: Vec<String> = affected
                .iter()
                .take(5)
                .map(|(v, p, ver, end)| {
                    let mut s = format!("{}:{}", v, p);
                    if let Some(ref version) = ver {
                        s.push_str(&format!(" v{}", version));
                    }
                    if let Some(ref e) = end {
                        s.push_str(&format!(" (up to {})", e));
                    }
                    s
                })
                .collect();
            summary.push_str(&version_info.join(", "));
            summary.push('\n');
        }

        if !cve.references.is_empty() {
            summary.push_str("- **References**:\n");
            for r in cve.references.iter().take(3) {
                let tags = if r.tags.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", r.tags.join(", "))
                };
                summary.push_str(&format!("  - {}{}\n", r.url, tags));
            }
        }

        if let Some(ref kev) = m.kev_entry {
            summary.push_str("- **CISA KEV**: YES - Known Exploited Vulnerability\n");
            summary.push_str(&format!("- **KEV Date Added**: {}\n", kev.date_added));
            summary.push_str(&format!("- **KEV Due Date**: {}\n", kev.due_date));
            summary.push_str(&format!(
                "- **Ransomware Campaign Use**: {}\n",
                kev.known_ransomware_campaign_use
            ));
            summary.push_str(&format!("- **Required Action**: {}\n", kev.required_action));
        } else {
            summary
                .push_str("- **CISA KEV**: No (not in Known Exploited Vulnerabilities catalog)\n");
        }

        summary.push('\n');
    }

    summary
}

#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    temperature: f32,
    messages: Vec<ClaudeMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClaudeMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    content: Vec<ClaudeContent>,
}

#[derive(Debug, Deserialize)]
struct ClaudeContent {
    text: String,
}

struct ClaudeClient {
    client: Client,
    api_key: String,
    model: String,
}

impl ClaudeClient {
    fn new(api_key: String, model: String) -> Result<Self, NvdError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;

        Ok(Self {
            client,
            api_key,
            model,
        })
    }

    async fn analyze_vulnerabilities(
        &self,
        matches: &[VulnerabilityMatch],
        sbom_name: &str,
    ) -> Result<String, NvdError> {
        let prompt = build_analysis_prompt(matches, sbom_name);

        let request = ClaudeRequest {
            model: self.model.clone(),
            max_tokens: 8192,
            temperature: 0.1,
            messages: vec![ClaudeMessage {
                role: "user".to_string(),
                content: prompt,
            }],
        };

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(NvdError::ApiError(format!(
                "Claude API error {}: {}",
                status, body
            )));
        }

        let claude_response: ClaudeResponse = response.json().await?;

        Ok(claude_response
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_else(|| "No response from Claude".to_string()))
    }
}

#[derive(Debug, Serialize)]
struct OpenAiRequest {
    model: String,
    input: Vec<OpenAiInputMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning: Option<OpenAiReasoning>,
}

#[derive(Debug, Serialize)]
struct OpenAiInputMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OpenAiReasoning {
    effort: String,
}

struct OpenAiClient {
    client: Client,
    api_key: String,
    model: String,
    reasoning_effort: Option<ReasoningEffort>,
}

impl OpenAiClient {
    fn new(
        api_key: String,
        model: String,
        reasoning_effort: Option<ReasoningEffort>,
    ) -> Result<Self, NvdError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;

        Ok(Self {
            client,
            api_key,
            model,
            reasoning_effort,
        })
    }

    async fn analyze_vulnerabilities(
        &self,
        matches: &[VulnerabilityMatch],
        sbom_name: &str,
    ) -> Result<String, NvdError> {
        let prompt = build_analysis_prompt(matches, sbom_name);

        let request = OpenAiRequest {
            model: self.model.clone(),
            input: vec![OpenAiInputMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            reasoning: self.reasoning_effort.map(|effort| OpenAiReasoning {
                effort: effort.as_str().to_string(),
            }),
        };

        let response = self
            .client
            .post("https://api.openai.com/v1/responses")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(NvdError::ApiError(format!(
                "OpenAI API error {}: {}",
                status, body
            )));
        }

        let openai_response: serde_json::Value = response.json().await?;
        extract_openai_text(&openai_response).ok_or_else(|| {
            NvdError::ApiError("No textual response returned from OpenAI".to_string())
        })
    }
}

fn extract_openai_text(response: &serde_json::Value) -> Option<String> {
    if let Some(text) = response.get("output_text").and_then(|v| v.as_str()) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Some(output_text) = response.get("output_text").and_then(|v| v.as_array()) {
        let text = output_text
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        if !text.is_empty() {
            return Some(text);
        }
    }

    if let Some(output_items) = response.get("output").and_then(|v| v.as_array()) {
        let mut parts = Vec::new();
        for item in output_items {
            if let Some(content_items) = item.get("content").and_then(|v| v.as_array()) {
                for content in content_items {
                    if let Some(text) = content.get("text").and_then(|v| v.as_str()) {
                        let trimmed = text.trim();
                        if !trimmed.is_empty() {
                            parts.push(trimmed.to_string());
                        }
                    }
                }
            }
        }

        if !parts.is_empty() {
            return Some(parts.join("\n\n"));
        }
    }

    if let Some(content) = response
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
    {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    None
}

// ============================================================================
// CVE Helper Methods
// ============================================================================

impl Cve {
    pub fn english_description(&self) -> Option<&str> {
        self.descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value.as_str())
    }

    pub fn highest_cvss_score(&self) -> Option<(f64, String)> {
        if let Some(ref metrics) = self.metrics {
            if let Some(metric) = metrics.cvss_metric_v40.first() {
                return Some((
                    metric.cvss_data.base_score,
                    format!("CVSS v4.0: {}", metric.cvss_data.base_severity),
                ));
            }
            if let Some(metric) = metrics.cvss_metric_v31.first() {
                return Some((
                    metric.cvss_data.base_score,
                    format!("CVSS v3.1: {}", metric.cvss_data.base_severity),
                ));
            }
            if let Some(metric) = metrics.cvss_metric_v30.first() {
                return Some((
                    metric.cvss_data.base_score,
                    format!("CVSS v3.0: {}", metric.cvss_data.base_severity),
                ));
            }
            if let Some(metric) = metrics.cvss_metric_v2.first() {
                let severity = metric.base_severity.as_deref().unwrap_or("N/A");
                return Some((
                    metric.cvss_data.base_score,
                    format!("CVSS v2.0: {}", severity),
                ));
            }
        }
        None
    }

    pub fn base_score(&self) -> Option<f64> {
        self.highest_cvss_score().map(|(score, _)| score)
    }

    pub fn cwe_ids(&self) -> Vec<String> {
        self.weaknesses
            .iter()
            .flat_map(|w| &w.description)
            .filter(|d| d.lang == "en")
            .map(|d| d.value.clone())
            .collect()
    }

    /// Extract all vendor/product pairs from CPE configurations
    pub fn affected_products(&self) -> Vec<(String, String, Option<String>, Option<String>)> {
        let mut products = Vec::new();

        for config in &self.configurations {
            for node in &config.nodes {
                for cpe_match in &node.cpe_match {
                    if !cpe_match.vulnerable {
                        continue;
                    }

                    let parts: Vec<&str> = cpe_match.criteria.split(':').collect();
                    if parts.len() >= 5 {
                        let vendor = parts[3].to_lowercase();
                        let product = parts[4].to_lowercase();
                        let version = if parts.len() > 5 && parts[5] != "*" {
                            Some(parts[5].to_string())
                        } else {
                            None
                        };

                        // Include version range info
                        let version_end = cpe_match
                            .version_end_excluding
                            .clone()
                            .or_else(|| cpe_match.version_end_including.clone());

                        products.push((vendor, product, version, version_end));
                    }
                }
            }
        }

        products
    }
}

// ============================================================================
// Local SBOM Scanner
// ============================================================================

#[derive(Debug)]
pub struct VulnerabilityMatch {
    pub component: SbomComponent,
    pub cve: Cve,
    pub match_type: String,
    pub kev_entry: Option<KevVulnerability>,
}

pub fn scan_sbom_local(
    db: &CveDatabase,
    components: &[SbomComponent],
    min_severity: f64,
    kev_catalog: Option<&KevCatalog>,
) -> Vec<VulnerabilityMatch> {
    let mut matches = Vec::new();
    // Use HashSet for O(1) duplicate detection instead of O(n) linear search
    let mut seen: HashSet<(String, String)> = HashSet::new();

    println!(
        "Scanning {} components against {} CVEs...\n",
        components.len(),
        db.cve_count
    );

    // Build lookup index: product name -> CVEs
    let mut product_index: HashMap<String, Vec<&Cve>> = HashMap::new();
    for cve in db.iter() {
        for (vendor, product, _, _) in cve.affected_products() {
            product_index.entry(product.clone()).or_default().push(cve);
            // Also index by vendor:product
            product_index
                .entry(format!("{}:{}", vendor, product))
                .or_default()
                .push(cve);
        }
    }

    for component in components {
        let name_lower = component.name.to_lowercase();
        let version = component.version.as_deref();

        // Try exact product name match
        if let Some(cves) = product_index.get(&name_lower) {
            for cve in cves {
                if let Some(score) = cve.base_score() {
                    if score >= min_severity {
                        if version_matches(cve, version) {
                            let key = (cve.id.clone(), component.name.clone());
                            if seen.insert(key) {
                                matches.push(VulnerabilityMatch {
                                    component: component.clone(),
                                    cve: (*cve).clone(),
                                    match_type: "product name".to_string(),
                                    kev_entry: kev_catalog.and_then(|k| k.get(&cve.id).cloned()),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Try vendor:product match if we have vendor info
        if let Some(ref vendor) = component.vendor {
            let key = format!("{}:{}", vendor.to_lowercase(), name_lower);
            if let Some(cves) = product_index.get(&key) {
                for cve in cves {
                    if let Some(score) = cve.base_score() {
                        if score >= min_severity {
                            if version_matches(cve, version) {
                                let seen_key = (cve.id.clone(), component.name.clone());
                                if seen.insert(seen_key) {
                                    matches.push(VulnerabilityMatch {
                                        component: component.clone(),
                                        cve: (*cve).clone(),
                                        match_type: "vendor:product".to_string(),
                                        kev_entry: kev_catalog
                                            .and_then(|k| k.get(&cve.id).cloned()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try purl-based matching
        if let Some(ref purl) = component.purl {
            if let Some((vendor, product, _)) = parse_purl(purl) {
                let product_lower = product.to_lowercase();

                if let Some(cves) = product_index.get(&product_lower) {
                    for cve in cves {
                        if let Some(score) = cve.base_score() {
                            if score >= min_severity {
                                if version_matches(cve, version) {
                                    let seen_key = (cve.id.clone(), component.name.clone());
                                    if seen.insert(seen_key) {
                                        matches.push(VulnerabilityMatch {
                                            component: component.clone(),
                                            cve: (*cve).clone(),
                                            match_type: "purl".to_string(),
                                            kev_entry: kev_catalog
                                                .and_then(|k| k.get(&cve.id).cloned()),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                // Also try vendor:product from purl
                let key = format!("{}:{}", vendor.to_lowercase(), product_lower);
                if let Some(cves) = product_index.get(&key) {
                    for cve in cves {
                        if let Some(score) = cve.base_score() {
                            if score >= min_severity {
                                if version_matches(cve, version) {
                                    let seen_key = (cve.id.clone(), component.name.clone());
                                    if seen.insert(seen_key) {
                                        matches.push(VulnerabilityMatch {
                                            component: component.clone(),
                                            cve: (*cve).clone(),
                                            match_type: "purl vendor:product".to_string(),
                                            kev_entry: kev_catalog
                                                .and_then(|k| k.get(&cve.id).cloned()),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort by: KEV status first, then ransomware, then due date urgency, then CVSS score
    matches.sort_by(|a, b| {
        let a_is_kev = a.kev_entry.is_some();
        let b_is_kev = b.kev_entry.is_some();

        // KEV entries sort above non-KEV entries
        match (a_is_kev, b_is_kev) {
            (true, false) => return std::cmp::Ordering::Less,
            (false, true) => return std::cmp::Ordering::Greater,
            _ => {}
        }

        // Within KEV tier: ransomware entries sort above non-ransomware
        if a_is_kev && b_is_kev {
            let a_ransom = a
                .kev_entry
                .as_ref()
                .map(|k| k.known_ransomware_campaign_use == "Known")
                .unwrap_or(false);
            let b_ransom = b
                .kev_entry
                .as_ref()
                .map(|k| k.known_ransomware_campaign_use == "Known")
                .unwrap_or(false);
            match (a_ransom, b_ransom) {
                (true, false) => return std::cmp::Ordering::Less,
                (false, true) => return std::cmp::Ordering::Greater,
                _ => {}
            }

            // Then by due date (earliest/most urgent first)
            let a_due = a
                .kev_entry
                .as_ref()
                .map(|k| k.due_date.as_str())
                .unwrap_or("9999-99-99");
            let b_due = b
                .kev_entry
                .as_ref()
                .map(|k| k.due_date.as_str())
                .unwrap_or("9999-99-99");
            if a_due != b_due {
                return a_due.cmp(b_due);
            }
        }

        // Finally, by CVSS score descending
        let score_a = a.cve.base_score().unwrap_or(0.0);
        let score_b = b.cve.base_score().unwrap_or(0.0);
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    matches
}

fn version_matches(cve: &Cve, component_version: Option<&str>) -> bool {
    let component_version = match component_version {
        Some(v) => v,
        None => return true, // If no version specified, assume it could match
    };

    for (_, _, cve_version, version_end) in cve.affected_products() {
        // If CVE specifies a version range
        if let Some(ref end) = version_end {
            if component_version < end.as_str() {
                return true;
            }
        }

        // If CVE specifies exact version
        if let Some(ref v) = cve_version {
            if v == component_version || v == "*" {
                return true;
            }
        }

        // If CVE has no version restriction (wildcard)
        if cve_version.is_none() {
            return true;
        }
    }

    // If we couldn't determine version info, assume it might match
    cve.affected_products().is_empty()
}

// ============================================================================
// Display Functions
// ============================================================================

fn display_cve(cve: &Cve, verbose: bool) {
    println!("CVE ID: {}", cve.id);
    println!("  Published: {}", cve.published);
    println!("  Status: {}", cve.vuln_status.as_deref().unwrap_or("N/A"));

    if let Some((score, severity)) = cve.highest_cvss_score() {
        println!("  Score: {:.1} ({})", score, severity);
    }

    let cwes = cve.cwe_ids();
    if !cwes.is_empty() {
        println!("  CWEs: {}", cwes.join(", "));
    }

    if let Some(desc) = cve.english_description() {
        let truncated = if !verbose && desc.len() > 200 {
            format!("{}...", &desc[..200])
        } else {
            desc.to_string()
        };
        println!("  Description: {}", truncated);
    }

    if verbose && !cve.references.is_empty() {
        println!("  References:");
        for r in cve.references.iter().take(5) {
            println!("    - {}", r.url);
        }
    }

    println!();
}

fn display_vulnerability_match(m: &VulnerabilityMatch) {
    println!("════════════════════════════════════════════════════════════════");
    println!(
        "Component: {} {}",
        m.component.name,
        m.component
            .version
            .as_deref()
            .unwrap_or("(unknown version)")
    );
    if let Some(ref purl) = m.component.purl {
        println!("  PURL: {}", purl);
    }
    println!("  Match type: {}", m.match_type);

    if let Some(ref kev) = m.kev_entry {
        println!();
        println!("  *** CISA KEV: KNOWN EXPLOITED VULNERABILITY ***");
        println!("  KEV Date Added: {}", kev.date_added);
        println!("  KEV Due Date:   {}", kev.due_date);
        println!("  Ransomware Use: {}", kev.known_ransomware_campaign_use);
        println!("  Required Action: {}", kev.required_action);
        if let Some(ref notes) = kev.notes {
            if !notes.is_empty() {
                println!("  CISA Notes: {}", notes);
            }
        }
    }

    println!();
    display_cve(&m.cve, false);
}

fn format_scan_output(
    matches: &[VulnerabilityMatch],
    sbom_name: &str,
    min_severity: f64,
    scan_time_ms: f64,
    format: &str,
) -> String {
    let critical = matches
        .iter()
        .filter(|m| m.cve.base_score().unwrap_or(0.0) >= 9.0)
        .count();
    let high = matches
        .iter()
        .filter(|m| {
            let s = m.cve.base_score().unwrap_or(0.0);
            s >= 7.0 && s < 9.0
        })
        .count();
    let medium = matches
        .iter()
        .filter(|m| {
            let s = m.cve.base_score().unwrap_or(0.0);
            s >= 4.0 && s < 7.0
        })
        .count();
    let low = matches
        .iter()
        .filter(|m| m.cve.base_score().unwrap_or(0.0) < 4.0)
        .count();
    let kev_count = matches.iter().filter(|m| m.kev_entry.is_some()).count();
    let ransomware_count = matches
        .iter()
        .filter(|m| {
            m.kev_entry
                .as_ref()
                .map(|k| k.known_ransomware_campaign_use == "Known")
                .unwrap_or(false)
        })
        .count();

    match format {
        "json" => {
            let json_output = serde_json::json!({
                "sbom": sbom_name,
                "scan_date": Utc::now().to_rfc3339(),
                "scan_time_ms": scan_time_ms,
                "total_vulnerabilities": matches.len(),
                "min_severity_filter": min_severity,
                "summary": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "kev_count": kev_count,
                    "ransomware_associated": ransomware_count,
                },
                "vulnerabilities": matches.iter().map(|m| {
                    serde_json::json!({
                        "cve_id": m.cve.id,
                        "component": m.component.name,
                        "version": m.component.version,
                        "cvss_score": m.cve.base_score(),
                        "match_type": m.match_type,
                        "in_kev": m.kev_entry.is_some(),
                        "ransomware_use": m.kev_entry.as_ref()
                            .map(|k| k.known_ransomware_campaign_use.clone()),
                        "kev_due_date": m.kev_entry.as_ref()
                            .map(|k| k.due_date.clone()),
                        "kev_required_action": m.kev_entry.as_ref()
                            .map(|k| k.required_action.clone()),
                        "description": m.cve.english_description()
                    })
                }).collect::<Vec<_>>()
            });
            serde_json::to_string_pretty(&json_output).unwrap_or_default()
        }
        "markdown" => {
            let mut md = String::new();
            md.push_str("# Vulnerability Scan Report\n\n");
            md.push_str(&format!("**SBOM**: {}\n\n", sbom_name));
            md.push_str(&format!(
                "**Date**: {}\n\n",
                Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            ));
            md.push_str(&format!("**Scan Time**: {:.2}ms\n\n", scan_time_ms));
            md.push_str(&format!("**Total Vulnerabilities**: {}\n\n", matches.len()));
            md.push_str(&format!(
                "**CISA KEV Matches**: {} of {} in Known Exploited Vulnerabilities catalog\n\n",
                kev_count,
                matches.len()
            ));
            if ransomware_count > 0 {
                md.push_str(&format!(
                    "**Ransomware Associated**: {}\n\n",
                    ransomware_count
                ));
            }
            md.push_str(&format!(
                "**Minimum Severity Filter**: {:.1}\n\n",
                min_severity
            ));

            md.push_str("## Summary\n\n");
            md.push_str("| Severity | Count |\n|----------|-------|\n");
            md.push_str(&format!("| Critical (9.0+) | {} |\n", critical));
            md.push_str(&format!("| High (7.0-8.9) | {} |\n", high));
            md.push_str(&format!("| Medium (4.0-6.9) | {} |\n", medium));
            md.push_str(&format!("| Low (0.0-3.9) | {} |\n", low));
            md.push_str(&format!(
                "| **CISA KEV (Exploited)** | **{}** |\n",
                kev_count
            ));
            if ransomware_count > 0 {
                md.push_str(&format!(
                    "| Ransomware Associated | {} |\n",
                    ransomware_count
                ));
            }

            md.push_str("\n## Vulnerabilities\n\n");
            md.push_str("| # | CVE ID | Component | CVSS | KEV | Description |\n");
            md.push_str("|---|--------|-----------|------|-----|-------------|\n");
            for (idx, m) in matches.iter().enumerate() {
                let score = m
                    .cve
                    .base_score()
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "N/A".to_string());
                let kev_status = if m.kev_entry.is_some() {
                    "**YES**"
                } else {
                    "No"
                };
                let desc = m
                    .cve
                    .english_description()
                    .unwrap_or("No description")
                    .chars()
                    .take(100)
                    .collect::<String>();
                md.push_str(&format!(
                    "| {} | {} | {} {} | {} | {} | {}... |\n",
                    idx + 1,
                    m.cve.id,
                    m.component.name,
                    m.component.version.as_deref().unwrap_or(""),
                    score,
                    kev_status,
                    desc.replace('|', "\\|")
                ));
            }

            // Detail section for KEV entries
            let kev_matches: Vec<_> = matches.iter().filter(|m| m.kev_entry.is_some()).collect();
            if !kev_matches.is_empty() {
                md.push_str("\n## CISA KEV Details\n\n");
                for m in &kev_matches {
                    if let Some(ref kev) = m.kev_entry {
                        md.push_str(&format!("### {} - {}\n\n", m.cve.id, m.component.name));
                        md.push_str(&format!("- **Date Added**: {}\n", kev.date_added));
                        md.push_str(&format!("- **Due Date**: {}\n", kev.due_date));
                        md.push_str(&format!(
                            "- **Ransomware Use**: {}\n",
                            kev.known_ransomware_campaign_use
                        ));
                        md.push_str(&format!(
                            "- **Required Action**: {}\n\n",
                            kev.required_action
                        ));
                    }
                }
            }

            md
        }
        _ => {
            // Plain text format
            let mut text = String::new();
            text.push_str("VULNERABILITY SCAN REPORT\n");
            text.push_str(&format!("SBOM: {}\n", sbom_name));
            text.push_str(&format!(
                "Date: {}\n",
                Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            ));
            text.push_str(&format!("Scan Time: {:.2}ms\n", scan_time_ms));
            text.push_str(&format!("Vulnerabilities: {}\n", matches.len()));
            text.push_str(&format!(
                "CISA KEV Matches: {} of {} in Known Exploited Vulnerabilities catalog\n",
                kev_count,
                matches.len()
            ));
            if ransomware_count > 0 {
                text.push_str(&format!("Ransomware Associated: {}\n", ransomware_count));
            }
            text.push_str(&format!("Min Severity: {:.1}\n", min_severity));
            text.push_str(&format!("\n{}\n\n", "=".repeat(60)));
            text.push_str(&format!("Critical (9.0+): {}\n", critical));
            text.push_str(&format!("High (7.0-8.9):  {}\n", high));
            text.push_str(&format!("Medium (4.0-6.9): {}\n", medium));
            text.push_str(&format!("Low (0.0-3.9):   {}\n", low));
            text.push_str(&format!("\n{}\n\n", "-".repeat(60)));

            for (idx, m) in matches.iter().enumerate() {
                let score = m
                    .cve
                    .base_score()
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "N/A".to_string());
                let kev_tag = if m.kev_entry.is_some() { " [KEV]" } else { "" };
                text.push_str(&format!(
                    "{}. {} | {} {} | CVSS: {}{}\n",
                    idx + 1,
                    m.cve.id,
                    m.component.name,
                    m.component.version.as_deref().unwrap_or(""),
                    score,
                    kev_tag
                ));
                if let Some(ref kev) = m.kev_entry {
                    text.push_str(&format!("   CISA KEV: Known Exploited Vulnerability\n"));
                    text.push_str(&format!(
                        "   Due Date: {} | Ransomware: {}\n",
                        kev.due_date, kev.known_ransomware_campaign_use
                    ));
                    text.push_str(&format!("   Required Action: {}\n", kev.required_action));
                }
                if let Some(desc) = m.cve.english_description() {
                    let truncated = if desc.len() > 200 {
                        format!("{}...", &desc[..200])
                    } else {
                        desc.to_string()
                    };
                    text.push_str(&format!("   {}\n", truncated));
                }
                text.push('\n');
            }

            text
        }
    }
}

fn display_kev_status(kev: &KevCatalog, cve_id: &str) {
    if let Some(entry) = kev.get(cve_id) {
        println!("*** CISA KEV STATUS: KNOWN EXPLOITED ***");
        println!("  Date Added: {}", entry.date_added);
        println!("  Due Date: {}", entry.due_date);
        println!("  Ransomware Use: {}", entry.known_ransomware_campaign_use);
        println!("  Required Action: {}", entry.required_action);
        if let Some(ref notes) = entry.notes {
            if !notes.is_empty() {
                println!("  CISA Notes: {}", notes);
            }
        }
        println!();
    } else {
        println!("CISA KEV Status: Not in KEV catalog\n");
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), NvdError> {
    dotenvy::dotenv().ok();

    let cli = Cli::parse();

    let api_key = std::env::var("NVD_API_KEY").ok();
    let client = NvdClient::new(api_key.clone());

    match cli.command {
        Commands::Sync {
            days,
            force,
            no_kev,
        } => {
            if api_key.is_some() {
                println!("Using NVD API key for higher rate limits\n");
            } else {
                println!("No API key found. Sync will be slower.");
                println!("Set NVD_API_KEY env var for faster sync.\n");
            }

            let days = days.min(120); // NVD max is 120 days

            let mut db = if force {
                println!("Force sync: creating new database");
                CveDatabase::new()
            } else {
                CveDatabase::load()?
            };

            println!("Syncing CVEs from the last {} days...\n", days);
            let cves = client.sync_cves(days).await?;

            println!("\nAdding {} CVEs to database...", cves.len());
            db.add_cves(cves);
            db.sync_days = days;
            db.save()?;

            println!("Database saved to: {:?}", CveDatabase::get_db_path()?);
            println!("Total CVEs in database: {}", db.cve_count);

            // Sync KEV catalog
            if !no_kev {
                println!();
                match client.fetch_kev_catalog().await {
                    Ok(response) => {
                        let mut kev_catalog = KevCatalog::new();
                        kev_catalog.update_from_response(response);
                        kev_catalog.save()?;
                        println!("KEV catalog saved to: {:?}", KevCatalog::get_db_path()?);
                        println!("Total KEV entries: {}", kev_catalog.kev_count);
                        println!("Ransomware-associated: {}", kev_catalog.ransomware_count());
                    }
                    Err(e) => {
                        eprintln!("WARNING: Failed to sync KEV catalog: {}", e);
                        eprintln!("CVE sync completed successfully. KEV can be retried later.");
                    }
                }
            }
        }

        Commands::Scan {
            sbom,
            min_severity,
            output,
            output_file,
            kev_file,
        } => {
            let db = CveDatabase::load()?;

            if db.cve_count == 0 {
                println!("CVE database is empty. Run 'sync' first:");
                println!("  cargo run -- sync --days 30");
                return Ok(());
            }

            println!(
                "Database: {} CVEs (last sync: {})\n",
                db.cve_count, db.last_sync
            );

            // Fetch fresh KEV catalog
            let kev_catalog = load_kev_live(&client, kev_file.as_ref()).await;

            println!("Loading SBOM from: {}\n", sbom.display());

            let components = parse_sbom(&sbom)?;
            println!("Found {} components in SBOM\n", components.len());

            let start = std::time::Instant::now();
            let matches = scan_sbom_local(&db, &components, min_severity, kev_catalog.as_ref());
            let elapsed = start.elapsed();

            let sbom_name = sbom
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            let scan_time_ms = elapsed.as_secs_f64() * 1000.0;

            // Build formatted output if writing to file or non-text format
            if output_file.is_some() || output != "text" {
                let output_content =
                    format_scan_output(&matches, sbom_name, min_severity, scan_time_ms, &output);

                if let Some(ref file_path) = output_file {
                    std::fs::write(file_path, &output_content)?;
                    println!("Scan results saved to: {}", file_path.display());
                } else {
                    println!("{}", output_content);
                }
            } else {
                // Default text output to console
                println!("════════════════════════════════════════════════════════════════");
                println!("                    VULNERABILITY SCAN RESULTS                   ");
                println!("════════════════════════════════════════════════════════════════\n");
                println!("Scan completed in {:.2}ms\n", scan_time_ms);

                if matches.is_empty() {
                    println!(
                        "No vulnerabilities found matching criteria (min severity: {:.1})",
                        min_severity
                    );
                } else {
                    println!(
                        "Found {} vulnerabilities (min severity: {:.1})\n",
                        matches.len(),
                        min_severity
                    );

                    let critical = matches
                        .iter()
                        .filter(|m| m.cve.base_score().unwrap_or(0.0) >= 9.0)
                        .count();
                    let high = matches
                        .iter()
                        .filter(|m| {
                            let s = m.cve.base_score().unwrap_or(0.0);
                            s >= 7.0 && s < 9.0
                        })
                        .count();
                    let medium = matches
                        .iter()
                        .filter(|m| {
                            let s = m.cve.base_score().unwrap_or(0.0);
                            s >= 4.0 && s < 7.0
                        })
                        .count();
                    let low = matches
                        .iter()
                        .filter(|m| m.cve.base_score().unwrap_or(0.0) < 4.0)
                        .count();

                    println!("Summary:");
                    println!("  Critical (9.0+): {}", critical);
                    println!("  High (7.0-8.9):  {}", high);
                    println!("  Medium (4.0-6.9): {}", medium);
                    println!("  Low (0.0-3.9):   {}", low);

                    // KEV summary
                    let kev_count = matches.iter().filter(|m| m.kev_entry.is_some()).count();
                    let ransomware_count = matches
                        .iter()
                        .filter(|m| {
                            m.kev_entry
                                .as_ref()
                                .map(|k| k.known_ransomware_campaign_use == "Known")
                                .unwrap_or(false)
                        })
                        .count();

                    if kev_count > 0 {
                        println!();
                        println!("  CISA KEV:");
                        println!("    Known Exploited: {}", kev_count);
                        if ransomware_count > 0 {
                            println!("    Ransomware Associated: {}", ransomware_count);
                        }
                    }

                    println!();

                    for m in &matches {
                        display_vulnerability_match(m);
                    }
                }
            }
        }

        Commands::Analyze {
            sbom,
            min_severity,
            output,
            output_file,
            kev_file,
            ai_provider,
            ai_model,
            reasoning_effort,
        } => {
            let ai_config = match resolve_ai_config(ai_provider, ai_model, reasoning_effort) {
                Ok(config) => config,
                Err(e) => {
                    println!("Error: {}", e);
                    return Ok(());
                }
            };

            if ai_config.provider == AiProvider::Claude && reasoning_effort.is_some() {
                println!("Note: --reasoning-effort is ignored when using Claude.");
                println!();
            }

            let ai_api_key = match resolve_ai_api_key(ai_config.provider) {
                Ok(key) => key,
                Err(e) => {
                    println!("Error: {}", e);
                    return Ok(());
                }
            };

            let ai_client = build_ai_client(&ai_config, ai_api_key)?;

            let db = CveDatabase::load()?;

            if db.cve_count == 0 {
                println!("CVE database is empty. Run 'sync' first:");
                println!("  cargo run -- sync --days 30");
                return Ok(());
            }

            println!(
                "Database: {} CVEs (last sync: {})\n",
                db.cve_count, db.last_sync
            );

            // Fetch fresh KEV catalog
            let kev_catalog = load_kev_live(&client, kev_file.as_ref()).await;

            println!("Loading SBOM from: {}\n", sbom.display());

            let components = parse_sbom(&sbom)?;
            println!("Found {} components in SBOM\n", components.len());

            // Scan for vulnerabilities
            println!("Scanning for vulnerabilities...");
            let matches = scan_sbom_local(&db, &components, min_severity, kev_catalog.as_ref());

            if matches.is_empty() {
                println!(
                    "\nNo vulnerabilities found matching criteria (min severity: {:.1})",
                    min_severity
                );
                return Ok(());
            }

            println!(
                "Found {} vulnerabilities (min severity: {:.1})\n",
                matches.len(),
                min_severity
            );

            println!(
                "Analyzing vulnerabilities with {} (model: {})...\n",
                ai_client.provider_name(),
                ai_client.model_name()
            );
            if let AiClient::OpenAi(client) = &ai_client {
                if let Some(effort) = client.reasoning_effort {
                    println!("OpenAI reasoning effort: {}\n", effort.as_str());
                }
            }

            let sbom_name = sbom
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            let analysis = ai_client
                .analyze_vulnerabilities(&matches, sbom_name)
                .await?;

            // Format output based on requested format
            let output_content = match output.as_str() {
                "json" => {
                    // Wrap analysis in JSON structure
                    let json_output = serde_json::json!({
                        "sbom": sbom_name,
                        "scan_date": Utc::now().to_rfc3339(),
                        "total_vulnerabilities": matches.len(),
                        "min_severity_filter": min_severity,
                        "ai_provider": ai_config.provider.as_str(),
                        "ai_model": ai_client.model_name(),
                        "analysis": analysis,
                        "vulnerabilities": matches.iter().map(|m| {
                            serde_json::json!({
                                "cve_id": m.cve.id,
                                "component": m.component.name,
                                "version": m.component.version,
                                "cvss_score": m.cve.base_score(),
                                "in_kev": m.kev_entry.is_some(),
                                "ransomware_use": m.kev_entry.as_ref()
                                    .map(|k| k.known_ransomware_campaign_use.clone()),
                                "kev_due_date": m.kev_entry.as_ref()
                                    .map(|k| k.due_date.clone()),
                                "description": m.cve.english_description()
                            })
                        }).collect::<Vec<_>>()
                    });
                    serde_json::to_string_pretty(&json_output)?
                }
                "text" => {
                    // Plain text format
                    let mut text = String::new();
                    text.push_str("VULNERABILITY ANALYSIS REPORT\n");
                    text.push_str(&format!("SBOM: {}\n", sbom_name));
                    text.push_str(&format!(
                        "Date: {}\n",
                        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                    ));
                    text.push_str(&format!("Vulnerabilities: {}\n", matches.len()));
                    text.push_str(&format!("AI Provider: {}\n", ai_config.provider.as_str()));
                    text.push_str(&format!("AI Model: {}\n", ai_client.model_name()));
                    text.push_str(&format!("\n{}\n", "=".repeat(60)));
                    text.push_str(&analysis);
                    text
                }
                _ => {
                    // Markdown format (default)
                    let mut md = String::new();
                    md.push_str("# Vulnerability Analysis Report\n\n");
                    md.push_str(&format!("**SBOM**: {}\n\n", sbom_name));
                    md.push_str(&format!(
                        "**Date**: {}\n\n",
                        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                    ));
                    md.push_str(&format!("**Total Vulnerabilities**: {}\n\n", matches.len()));
                    md.push_str(&format!(
                        "**Minimum Severity Filter**: {:.1}\n\n",
                        min_severity
                    ));
                    md.push_str(&format!(
                        "**AI Provider**: {}\n\n",
                        ai_config.provider.as_str()
                    ));
                    md.push_str(&format!("**AI Model**: {}\n\n", ai_client.model_name()));
                    md.push_str("---\n\n");
                    md.push_str(&analysis);
                    md
                }
            };

            // Output results
            if let Some(ref file_path) = output_file {
                std::fs::write(file_path, &output_content)?;
                println!("Analysis saved to: {}", file_path.display());
            } else {
                println!("{}", output_content);
            }
        }

        Commands::Stats => {
            let db = CveDatabase::load()?;
            let path = CveDatabase::get_db_path()?;

            println!("CVE Database Statistics");
            println!("═══════════════════════════════════════");
            println!("  Location: {:?}", path);
            println!("  Last sync: {}", db.last_sync);
            println!("  Sync range: {} days", db.sync_days);
            println!("  Total CVEs: {}", db.cve_count);

            if db.cve_count > 0 {
                let critical = db
                    .iter()
                    .filter(|c| c.base_score().unwrap_or(0.0) >= 9.0)
                    .count();
                let high = db
                    .iter()
                    .filter(|c| {
                        let s = c.base_score().unwrap_or(0.0);
                        s >= 7.0 && s < 9.0
                    })
                    .count();
                let medium = db
                    .iter()
                    .filter(|c| {
                        let s = c.base_score().unwrap_or(0.0);
                        s >= 4.0 && s < 7.0
                    })
                    .count();

                println!("\n  By Severity:");
                println!("    Critical (9.0+): {}", critical);
                println!("    High (7.0-8.9):  {}", high);
                println!("    Medium (4.0-6.9): {}", medium);
            }

            // KEV catalog stats
            println!();
            let kev_catalog = load_kev_live(&client, None).await;
            match kev_catalog {
                Some(kev) if kev.kev_count > 0 => {
                    let kev_path = KevCatalog::get_db_path()?;
                    println!("CISA KEV Catalog Statistics");
                    println!("═══════════════════════════════════════");
                    println!("  Location: {:?}", kev_path);
                    println!("  Last sync: {}", kev.last_sync);
                    println!("  Catalog version: {}", kev.catalog_version);
                    println!("  Date released: {}", kev.date_released);
                    println!("  Total KEV entries: {}", kev.kev_count);
                    println!("  Ransomware-associated: {}", kev.ransomware_count());
                    println!("  Overdue (past due date): {}", kev.overdue_count());

                    // Show overlap with CVE database
                    if db.cve_count > 0 {
                        let overlap = kev
                            .vulnerabilities
                            .keys()
                            .filter(|cve_id| db.get(cve_id).is_some())
                            .count();
                        println!(
                            "  In local CVE DB: {} of {} ({:.1}%)",
                            overlap,
                            kev.kev_count,
                            (overlap as f64 / kev.kev_count as f64) * 100.0
                        );
                    }
                }
                _ => {
                    println!("CISA KEV Catalog: Not available");
                }
            }
        }

        Commands::Lookup { cve_id, kev_file } => {
            // Validate CVE ID format to prevent injection
            let cve_pattern = Regex::new(r"^CVE-\d{4}-\d{4,}$").unwrap();
            if !cve_pattern.is_match(&cve_id) {
                println!("Invalid CVE ID format. Expected: CVE-YYYY-NNNNN");
                return Ok(());
            }

            // Fetch fresh KEV catalog
            let kev_catalog = load_kev_live(&client, kev_file.as_ref()).await;

            // Try local DB first
            let db = CveDatabase::load()?;
            if let Some(cve) = db.get(&cve_id) {
                println!("Found in local database:\n");
                display_cve(cve, true);

                // Show KEV status
                if let Some(ref kev) = kev_catalog {
                    display_kev_status(kev, &cve_id);
                }
                return Ok(());
            }

            // Fall back to API
            println!("Not in local DB, querying NVD API...\n");
            let response = client.get_cve_by_id(&cve_id).await?;

            if response.vulnerabilities.is_empty() {
                println!("CVE not found: {}", cve_id);
            } else {
                display_cve(&response.vulnerabilities[0].cve, true);

                // Show KEV status
                if let Some(ref kev) = kev_catalog {
                    display_kev_status(kev, &cve_id);
                }
            }
        }

        Commands::Recent { days, limit } => {
            if api_key.is_some() {
                println!("Using NVD API key for higher rate limits\n");
            }

            let end_date = Utc::now();
            let start_date = end_date - Duration::days(days as i64);

            println!(
                "Fetching CVEs published between {} and {}",
                start_date.format("%Y-%m-%d %H:%M:%S UTC"),
                end_date.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!("-------------------------------------------\n");

            let response = client
                .get_cves_by_pub_date(start_date, end_date, 0, Some(limit))
                .await?;

            println!(
                "Total CVEs in last {} days: {}\n",
                days, response.total_results
            );

            for vuln in &response.vulnerabilities {
                display_cve(&vuln.cve, false);
            }
        }
    }

    Ok(())
}
