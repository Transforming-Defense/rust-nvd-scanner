# NVD CVE Scanner

A vulnerability scanner that checks your Software Bill of Materials (SBOM) against the National Vulnerability Database (NVD) and CISA KEV, with AI-powered analysis and remediation guidance.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-blue.svg)](https://www.rust-lang.org/)


## Features

- **📦 SBOM Support** - Parses CycloneDX and SPDX (JSON) formats
- **📚 Multi-SBOM Aggregation** - Scan a single SBOM file or an entire directory and consolidate findings into one prioritized report
- **🤖 AI-Powered Analysis** - Uses Claude or OpenAI/Codex to prioritize vulnerabilities and provide remediation guidance
- **🎯 Smart Matching** - Matches by CPE, PURL, vendor, and product name
- **📊 Multiple Output Formats** - Markdown, JSON, and plain text reports
- **🔒 Low Temperature AI** - Consistent, factual analysis without speculation
- **🛡️ CISA KEV Integration** - Automatically enriches results with the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, prioritizing actively exploited CVEs above all others

## Quick Start

### Prerequisites

- Rust 1.78 or later
- NVD API key (free) - [Request here](https://nvd.nist.gov/developers/request-an-api-key)
- AI API key (for analysis):
  - Claude (Anthropic): [Get one here](https://console.anthropic.com/)
  - OpenAI (Codex): [Get one here](https://platform.openai.com/)

### Installation

```bash
git clone https://github.com/scherrie-td/rust-nvd-scanner.git
cd rust-nvd-scanner
cargo build --release
```

### Configuration

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

```env
NVD_API_KEY=your-nvd-api-key-here
ANTHROPIC_API_KEY=your-claude-api-key-here
OPENAI_API_KEY=your-openai-api-key-here
AI_PROVIDER=claude
```

### Basic Usage

```bash
# 1. Sync the CVE database (one-time, then periodic updates)
cargo run -- sync --days 30

# 2. Scan your SBOM (file or directory)
cargo run -- scan --sbom ./your-sbom.json

# 3. Scan all SBOMs in a directory and consolidate report
cargo run -- scan --sbom ./sboms --output markdown -f report.md

# 4. Get AI-powered consolidated prioritization
cargo run -- analyze --sbom ./sboms --min-severity 7.0 -f report.md

# 5. Use OpenAI/Codex instead
cargo run -- analyze --sbom ./sboms --ai-provider openai --ai-model gpt-5.4 -f report.md
```

## Commands

### `sync` - Download CVEs to Local Database

Downloads CVEs from NVD and stores them locally for fast scanning.

```bash
# Sync last 7 days (default)
cargo run -- sync

# Sync last 30 days
cargo run -- sync --days 30

# Force full re-sync
cargo run -- sync --days 30 --force
```

**Options:**
- `-d, --days <DAYS>` - Number of days to sync (default: 7, max: 120)
- `-f, --force` - Force full re-sync, ignoring existing data
- `--no-kev` - Skip CISA KEV catalog sync

If you see an oversized local DB error, the scanner now prints an exact override command such as:

```bash
export RUST_NVD_SCANNER_DB_MAX_SIZE_BYTES=<recommended-by-error>
```

Then rerun your command. This keeps the default 500MB safety guard in place unless you opt in.

### `scan` - Scan SBOM Against Local Database

Fast local scan. Automatically fetches the latest CISA KEV catalog to enrich results with known exploitation status.

```bash
# Basic scan
cargo run -- scan --sbom ./sbom.json

# Scan all SBOM JSON files in a directory
cargo run -- scan --sbom ./sboms

# Filter by minimum severity
cargo run -- scan --sbom ./sbom.json --min-severity 7.0

# Save report as markdown
cargo run -- scan --sbom ./sbom.json -o markdown -f report.md

# Save report as JSON
cargo run -- scan --sbom ./sbom.json -o json -f report.json

# Use a manually downloaded KEV catalog (for air-gapped environments)
cargo run -- scan --sbom ./sbom.json --kev-file ./known_exploited_vulnerabilities.json
```

**Options:**
- `-s, --sbom <PATH>` - Path to an SBOM file, or a directory containing SBOM JSON files (required)
- `-m, --min-severity <SCORE>` - Minimum CVSS score to report (default: 0.0)
- `-o, --output <FORMAT>` - Output format: `text`, `json`, or `markdown` (default: text)
- `-f, --output-file <PATH>` - Save scan results to file
- `--kev-file <PATH>` - Path to a manually downloaded CISA KEV catalog JSON file

### `analyze` - AI-Powered Vulnerability Analysis

Scans your SBOM and uses your selected AI provider (Claude or OpenAI/Codex) to provide risk prioritization and remediation guidance. KEV data is included in the AI prompt so exploitation status is factored into prioritization.

```bash
# Analyze with markdown output
cargo run -- analyze --sbom ./sbom.json

# Analyze all SBOM JSON files in a directory with consolidated prioritization
cargo run -- analyze --sbom ./sboms

# Analyze with OpenAI Codex model
cargo run -- analyze --sbom ./sbom.json --ai-provider openai --ai-model gpt-5.3-codex

# Focus on critical vulnerabilities
cargo run -- analyze --sbom ./sbom.json --min-severity 9.0

# Save report to file
cargo run -- analyze --sbom ./sbom.json -f vulnerability-report.md

# JSON output
cargo run -- analyze --sbom ./sbom.json --output json -f report.json
```

**Options:**
- `-s, --sbom <PATH>` - Path to an SBOM file, or a directory containing SBOM JSON files (required)
- `-m, --min-severity <SCORE>` - Minimum CVSS score to analyze (default: 7.0)
- `-o, --output <FORMAT>` - Output format: `markdown`, `json`, or `text` (default: markdown)
- `-f, --output-file <PATH>` - Save analysis to file
- `--kev-file <PATH>` - Path to a manually downloaded CISA KEV catalog JSON file
- `--ai-provider <PROVIDER>` - AI provider: `claude` or `openai` (default: `AI_PROVIDER` env var, or `claude`)
- `--ai-model <MODEL>` - Override model name (default: `claude-sonnet-4-20250514` for Claude, `gpt-5.3-codex` for OpenAI)
- `--reasoning-effort <EFFORT>` - OpenAI reasoning effort: `none`, `minimal`, `low`, `medium`, `high`, `xhigh`

### `stats` - Database Statistics

View information about your local CVE and KEV databases.

```bash
cargo run -- stats
```

### `lookup` - Look Up Specific CVE

Search for a CVE by ID (checks local database first, then NVD API). Also shows CISA KEV status if the CVE is a known exploited vulnerability.

```bash
cargo run -- lookup CVE-2024-1234
```

**Options:**
- `--kev-file <PATH>` - Path to a manually downloaded CISA KEV catalog JSON file

### `recent` - Fetch Recent CVEs

Query NVD API directly for recent CVEs (does not save to database).

```bash
# Last 7 days
cargo run -- recent

# Last 14 days, limit to 50 results
cargo run -- recent --days 14 --limit 50
```

## Supported SBOM Formats

### CycloneDX (JSON)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20"
    }
  ]
}
```

### SPDX (JSON)

```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "lodash",
      "versionInfo": "4.17.20",
      "externalRefs": [
        {
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/lodash@4.17.20"
        }
      ]
    }
  ]
}
```

## How Matching Works

The scanner uses multiple strategies to match SBOM components to CVEs:

1. **CPE Match** - Direct match against NVD's CPE configurations
2. **PURL Match** - Parses package URLs to extract vendor/product/version
3. **Vendor:Product Match** - Matches against CPE vendor and product fields
4. **Name Match** - Fuzzy matching on component name

Version ranges are respected when specified in CVE configurations.

## CISA KEV Integration

The scanner automatically fetches the [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog on every scan. Vulnerabilities confirmed by CISA to be actively exploited in the wild are:

- **Sorted above all non-KEV vulnerabilities**, regardless of CVSS score (a CVSS 7.0 with active exploitation ranks above a CVSS 9.8 without)
- **Flagged with KEV badges** showing date added, remediation due date, ransomware association, and required action
- **Fed into AI analysis** so your configured model can factor exploitation status into its prioritization

Within the KEV tier, results are further sorted by:
1. Ransomware-associated CVEs first
2. Earliest remediation due date (most urgent)
3. CVSS score descending

The KEV catalog (~400KB) is cached locally for offline fallback. For air-gapped environments, use `--kev-file <path>` to provide a manually downloaded copy.

## AI Analysis

The `analyze` command supports Claude and OpenAI/Codex. Both use the same prompt and vulnerability context so output stays consistent across providers. The AI provides:

1. **Executive Summary** - Overall security posture assessment
2. **Risk-Prioritized List** - Vulnerabilities ranked by actual risk, considering CISA KEV status, ransomware association, CVSS score, attack vector, and source SBOM context
3. **Remediation Guidance** - For each CVE:
   - Immediate actions to take
   - Specific version to upgrade to
   - Workarounds if no fix is available
4. **Summary Table** - Quick reference for action planning
5. **CISA KEV Summary** - Overview of actively exploited vulnerabilities and compliance implications (BOD 22-01)

### Cost Estimate

Costs vary by provider and model. Use `--min-severity` to reduce cost by focusing on high-priority vulnerabilities.

## Examples

### Full Workflow

```bash
# Initial setup
cargo run -- sync --days 30

# Quick scan to see what you're dealing with
cargo run -- scan --sbom ./my-app-sbom.json

# Generate detailed report for critical/high vulnerabilities
cargo run -- analyze --sbom ./my-app-sbom.json \
  --min-severity 7.0 \
  --output markdown \
  -f security-report.md
```

### CI/CD Integration

```bash
#!/bin/bash
# Example CI script

# Update CVE database
cargo run -- sync --days 7

# Scan and fail if critical vulnerabilities found
OUTPUT=$(cargo run -- scan --sbom ./sbom.json --min-severity 9.0)

if echo "$OUTPUT" | grep -q "Critical (9.0+): [1-9]"; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

## Data Storage

The CVE database and KEV catalog are stored locally:

- **macOS**: `~/Library/Application Support/com.nvd.nvd-cve-scanner/`
- **Linux**: `~/.local/share/nvd-cve-scanner/`
- **Windows**: `C:\Users\<User>\AppData\Roaming\nvd\nvd-cve-scanner\data\`

Files:
- `cve_database.json` - Synced NVD CVE data
- `kev_catalog.json` - Cached CISA KEV catalog (auto-refreshed on each run)

## Rate Limits

### NVD API
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds

### Claude API
- Standard rate limits apply based on your Anthropic plan

### OpenAI API
- Standard rate limits apply based on your OpenAI plan

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for the CVE data
- [CISA Known Exploited Vulnerabilities Catalog (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for exploit data. 
- [Anthropic](https://www.anthropic.com/) for Claude AI
- [OpenAI](https://openai.com/) for Codex/OpenAI model support
- The Rust community for excellent crates

## Disclaimer

This tool is provided for informational purposes only. Always verify vulnerability findings and remediation steps before implementing changes in production environments. The AI analysis is meant to assist human decision-making, not replace it.
