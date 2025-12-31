# NVD CVE Scanner

A fast, local-first vulnerability scanner that checks your Software Bill of Materials (SBOM) against the National Vulnerability Database (NVD), with AI-powered analysis and remediation guidance.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-blue.svg)](https://www.rust-lang.org/)

## Why did I do this?

I've always wanted a simple tool to review the latest CVEs against the packages and libraries throughout my system inventory.  Since I have some holiday downtime, I felt this was a good time to kick it off.  I'm also using it as an opportunity to improve my rust skills as it's a new language for me.  Before you ask, of course I used AI I'd be a fool not to.  AI is a great learning tool. Especially when you build piece by piece like you do when you're coding from scratch, then run through and look for areas for improvement.  Please keep in mind this is a work in progress on my learning journey and also feel free to provide any advice that will make the code, and me, better!  

## Features

- **🚀 Fast Local Scanning** - Sync CVEs once, scan instantly without API calls
- **📦 SBOM Support** - Parses CycloneDX and SPDX (JSON) formats
- **🤖 AI-Powered Analysis** - Uses Claude to prioritize vulnerabilities and provide remediation guidance
- **🎯 Smart Matching** - Matches by CPE, PURL, vendor, and product name
- **📊 Multiple Output Formats** - Markdown, JSON, and plain text reports
- **🔒 Low Temperature AI** - Consistent, factual analysis without speculation

## Quick Start

### Prerequisites

- Rust 1.78 or later
- NVD API key (free) - [Request here](https://nvd.nist.gov/developers/request-an-api-key)
- Claude API key (for AI analysis) - [Get one here](https://console.anthropic.com/)

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
```

### Basic Usage

```bash
# 1. Sync the CVE database (one-time, then periodic updates)
cargo run -- sync --days 30

# 2. Scan your SBOM
cargo run -- scan --sbom ./your-sbom.json

# 3. Get AI-powered analysis
cargo run -- analyze --sbom ./your-sbom.json --min-severity 7.0 -f report.md
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

### `scan` - Scan SBOM Against Local Database

Fast local scan with no API calls required.

```bash
# Basic scan
cargo run -- scan --sbom ./sbom.json

# Filter by minimum severity
cargo run -- scan --sbom ./sbom.json --min-severity 7.0
```

**Options:**
- `-s, --sbom <PATH>` - Path to SBOM file (required)
- `-m, --min-severity <SCORE>` - Minimum CVSS score to report (default: 0.0)

### `analyze` - AI-Powered Vulnerability Analysis

Scans your SBOM and uses Claude to provide risk prioritization and remediation guidance.

```bash
# Analyze with markdown output
cargo run -- analyze --sbom ./sbom.json

# Focus on critical vulnerabilities
cargo run -- analyze --sbom ./sbom.json --min-severity 9.0

# Save report to file
cargo run -- analyze --sbom ./sbom.json -f vulnerability-report.md

# JSON output
cargo run -- analyze --sbom ./sbom.json --output json -f report.json
```

**Options:**
- `-s, --sbom <PATH>` - Path to SBOM file (required)
- `-m, --min-severity <SCORE>` - Minimum CVSS score to analyze (default: 7.0)
- `-o, --output <FORMAT>` - Output format: `markdown`, `json`, or `text` (default: markdown)
- `-f, --output-file <PATH>` - Save analysis to file

### `stats` - Database Statistics

View information about your local CVE database.

```bash
cargo run -- stats
```

### `lookup` - Look Up Specific CVE

Search for a CVE by ID (checks local database first, then NVD API).

```bash
cargo run -- lookup CVE-2024-1234
```

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

## AI Analysis

The `analyze` command uses Claude (Sonnet) with a low temperature (0.1) for consistent, factual analysis. The AI provides:

1. **Executive Summary** - Overall security posture assessment
2. **Risk-Prioritized List** - Vulnerabilities ranked by actual risk, not just CVSS score
3. **Remediation Guidance** - For each CVE:
   - Immediate actions to take
   - Specific version to upgrade to
   - Workarounds if no fix is available
4. **Summary Table** - Quick reference for action planning

### Cost Estimate

Approximate Claude API costs:
- ~100 CVEs: ~$0.15
- ~500 CVEs: ~$0.75
- ~1000 CVEs: ~$1.50

Use `--min-severity` to reduce costs by focusing on high-priority vulnerabilities.

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

The CVE database is stored locally:

- **macOS**: `~/Library/Application Support/com.nvd.nvd-cve-client/cve_database.json`
- **Linux**: `~/.local/share/nvd-cve-client/cve_database.json`
- **Windows**: `C:\Users\<User>\AppData\Roaming\nvd\nvd-cve-client\data\cve_database.json`

## Rate Limits

### NVD API
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds

### Claude API
- Standard rate limits apply based on your plan

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
- [Anthropic](https://www.anthropic.com/) for Claude AI
- The Rust community for excellent crates

## Disclaimer

This tool is provided for informational purposes only. Always verify vulnerability findings and remediation steps before implementing changes in production environments. The AI analysis is meant to assist human decision-making, not replace it.