use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
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
    },

    /// Scan an SBOM against the local CVE database (fast, no API calls)
    Scan {
        /// Path to the SBOM file (CycloneDX or SPDX JSON format)
        #[arg(short, long)]
        sbom: PathBuf,

        /// Only show vulnerabilities with CVSS score >= this value
        #[arg(short = 'm', long, default_value = "0.0")]
        min_severity: f64,
    },

    /// Analyze vulnerabilities with Claude AI for prioritization and remediation
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
    },

    /// Show database statistics
    Stats,

    /// Look up a specific CVE by ID (searches local DB first, then API)
    Lookup {
        /// CVE ID (e.g., CVE-2024-1234)
        cve_id: String,
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
        Regex::new(r"pkg:([^/]+)/(?:([^/]+)/)?([^@]+)(?:@(.+))?")
            .expect("Invalid PURL regex")
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
        if self.api_key.is_some() { 1 } else { 6 }
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
}

// ============================================================================
// Claude API Client
// ============================================================================

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

pub struct ClaudeClient {
    client: Client,
    api_key: String,
}

impl ClaudeClient {
    pub fn new(api_key: String) -> Self {
        // Build client with timeout for long AI responses
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120)) // AI responses can take time
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            api_key,
        }
    }

    pub async fn analyze_vulnerabilities(
        &self,
        matches: &[VulnerabilityMatch],
        sbom_name: &str,
    ) -> Result<String, NvdError> {
        // Build vulnerability summary for Claude
        let vuln_summary = self.build_vulnerability_summary(matches);

        let prompt = format!(
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
- CVSS score (use the exact scores provided)
- Exploitability (is there known exploitation in the wild based on the CVE data?)
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
Provide a table with columns: Priority | CVE ID | Component | CVSS | Recommended Action

Be concise but thorough. Focus on actionable guidance."#,
            sbom_name = sbom_name,
            count = matches.len(),
            vuln_summary = vuln_summary
        );

        let request = ClaudeRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 8192,
            temperature: 0.1, // Low temperature for factual, consistent analysis
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

    fn build_vulnerability_summary(&self, matches: &[VulnerabilityMatch]) -> String {
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

            // Add affected versions info
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

            // Add references
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

            summary.push('\n');
        }

        summary
    }
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
}

pub fn scan_sbom_local(
    db: &CveDatabase,
    components: &[SbomComponent],
    min_severity: f64,
) -> Vec<VulnerabilityMatch> {
    let mut matches = Vec::new();
    // Use HashSet for O(1) duplicate detection instead of O(n) linear search
    let mut seen: HashSet<(String, String)> = HashSet::new();

    println!("Scanning {} components against {} CVEs...\n", components.len(), db.cve_count);

    // Build lookup index: product name -> CVEs
    let mut product_index: HashMap<String, Vec<&Cve>> = HashMap::new();
    for cve in db.iter() {
        for (vendor, product, _, _) in cve.affected_products() {
            product_index
                .entry(product.clone())
                .or_default()
                .push(cve);
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

    // Sort by severity
    matches.sort_by(|a, b| {
        let score_a = a.cve.base_score().unwrap_or(0.0);
        let score_b = b.cve.base_score().unwrap_or(0.0);
        score_b.partial_cmp(&score_a).unwrap()
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
        m.component.version.as_deref().unwrap_or("(unknown version)")
    );
    if let Some(ref purl) = m.component.purl {
        println!("  PURL: {}", purl);
    }
    println!("  Match type: {}", m.match_type);
    println!();
    display_cve(&m.cve, false);
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
        Commands::Sync { days, force } => {
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
        }

        Commands::Scan { sbom, min_severity } => {
            let db = CveDatabase::load()?;

            if db.cve_count == 0 {
                println!("CVE database is empty. Run 'sync' first:");
                println!("  cargo run -- sync --days 30");
                return Ok(());
            }

            println!("Database: {} CVEs (last sync: {})\n", db.cve_count, db.last_sync);
            println!("Loading SBOM from: {}\n", sbom.display());

            let components = parse_sbom(&sbom)?;
            println!("Found {} components in SBOM\n", components.len());

            let start = std::time::Instant::now();
            let matches = scan_sbom_local(&db, &components, min_severity);
            let elapsed = start.elapsed();

            println!("════════════════════════════════════════════════════════════════");
            println!("                    VULNERABILITY SCAN RESULTS                   ");
            println!("════════════════════════════════════════════════════════════════\n");
            println!("Scan completed in {:.2}ms\n", elapsed.as_secs_f64() * 1000.0);

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

                let critical = matches.iter().filter(|m| m.cve.base_score().unwrap_or(0.0) >= 9.0).count();
                let high = matches.iter().filter(|m| {
                    let s = m.cve.base_score().unwrap_or(0.0);
                    s >= 7.0 && s < 9.0
                }).count();
                let medium = matches.iter().filter(|m| {
                    let s = m.cve.base_score().unwrap_or(0.0);
                    s >= 4.0 && s < 7.0
                }).count();
                let low = matches.iter().filter(|m| m.cve.base_score().unwrap_or(0.0) < 4.0).count();

                println!("Summary:");
                println!("  🔴 Critical (9.0+): {}", critical);
                println!("  🟠 High (7.0-8.9):  {}", high);
                println!("  🟡 Medium (4.0-6.9): {}", medium);
                println!("  🟢 Low (0.0-3.9):   {}", low);
                println!();

                for m in &matches {
                    display_vulnerability_match(m);
                }
            }
        }

        Commands::Analyze {
            sbom,
            min_severity,
            output,
            output_file,
        } => {
            // Check for Claude API key
            let claude_api_key = std::env::var("ANTHROPIC_API_KEY").or_else(|_| std::env::var("CLAUDE_API_KEY"));
            let claude_api_key = match claude_api_key {
                Ok(key) => key,
                Err(_) => {
                    println!("Error: Claude API key not found.");
                    println!("Set ANTHROPIC_API_KEY or CLAUDE_API_KEY in your .env file.");
                    return Ok(());
                }
            };

            let db = CveDatabase::load()?;

            if db.cve_count == 0 {
                println!("CVE database is empty. Run 'sync' first:");
                println!("  cargo run -- sync --days 30");
                return Ok(());
            }

            println!("Database: {} CVEs (last sync: {})\n", db.cve_count, db.last_sync);
            println!("Loading SBOM from: {}\n", sbom.display());

            let components = parse_sbom(&sbom)?;
            println!("Found {} components in SBOM\n", components.len());

            // Scan for vulnerabilities
            println!("Scanning for vulnerabilities...");
            let matches = scan_sbom_local(&db, &components, min_severity);

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

            // Analyze with Claude
            println!("Analyzing vulnerabilities with Claude AI...\n");
            println!("(Using low temperature for consistent, factual analysis)\n");

            let claude_client = ClaudeClient::new(claude_api_key);
            let sbom_name = sbom.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            let analysis = claude_client.analyze_vulnerabilities(&matches, sbom_name).await?;

            // Format output based on requested format
            let output_content = match output.as_str() {
                "json" => {
                    // Wrap analysis in JSON structure
                    let json_output = serde_json::json!({
                        "sbom": sbom_name,
                        "scan_date": Utc::now().to_rfc3339(),
                        "total_vulnerabilities": matches.len(),
                        "min_severity_filter": min_severity,
                        "analysis": analysis,
                        "vulnerabilities": matches.iter().map(|m| {
                            serde_json::json!({
                                "cve_id": m.cve.id,
                                "component": m.component.name,
                                "version": m.component.version,
                                "cvss_score": m.cve.base_score(),
                                "description": m.cve.english_description()
                            })
                        }).collect::<Vec<_>>()
                    });
                    serde_json::to_string_pretty(&json_output)?
                }
                "text" => {
                    // Plain text format
                    let mut text = String::new();
                    text.push_str(&format!("VULNERABILITY ANALYSIS REPORT\n"));
                    text.push_str(&format!("SBOM: {}\n", sbom_name));
                    text.push_str(&format!("Date: {}\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
                    text.push_str(&format!("Vulnerabilities: {}\n", matches.len()));
                    text.push_str(&format!("\n{}\n", "=".repeat(60)));
                    text.push_str(&analysis);
                    text
                }
                _ => {
                    // Markdown format (default)
                    let mut md = String::new();
                    md.push_str("# Vulnerability Analysis Report\n\n");
                    md.push_str(&format!("**SBOM**: {}\n\n", sbom_name));
                    md.push_str(&format!("**Date**: {}\n\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
                    md.push_str(&format!("**Total Vulnerabilities**: {}\n\n", matches.len()));
                    md.push_str(&format!("**Minimum Severity Filter**: {:.1}\n\n", min_severity));
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
                let critical = db.iter().filter(|c| c.base_score().unwrap_or(0.0) >= 9.0).count();
                let high = db.iter().filter(|c| {
                    let s = c.base_score().unwrap_or(0.0);
                    s >= 7.0 && s < 9.0
                }).count();
                let medium = db.iter().filter(|c| {
                    let s = c.base_score().unwrap_or(0.0);
                    s >= 4.0 && s < 7.0
                }).count();

                println!("\n  By Severity:");
                println!("    Critical (9.0+): {}", critical);
                println!("    High (7.0-8.9):  {}", high);
                println!("    Medium (4.0-6.9): {}", medium);
            }
        }

        Commands::Lookup { cve_id } => {
            // Validate CVE ID format to prevent injection
            let cve_pattern = Regex::new(r"^CVE-\d{4}-\d{4,}$").unwrap();
            if !cve_pattern.is_match(&cve_id) {
                println!("Invalid CVE ID format. Expected: CVE-YYYY-NNNNN");
                return Ok(());
            }

            // Try local DB first
            let db = CveDatabase::load()?;
            if let Some(cve) = db.get(&cve_id) {
                println!("Found in local database:\n");
                display_cve(cve, true);
                return Ok(());
            }

            // Fall back to API
            println!("Not in local DB, querying NVD API...\n");
            let response = client.get_cve_by_id(&cve_id).await?;

            if response.vulnerabilities.is_empty() {
                println!("CVE not found: {}", cve_id);
            } else {
                display_cve(&response.vulnerabilities[0].cve, true);
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

            println!("Total CVEs in last {} days: {}\n", days, response.total_results);

            for vuln in &response.vulnerabilities {
                display_cve(&vuln.cve, false);
            }
        }
    }

    Ok(())
}