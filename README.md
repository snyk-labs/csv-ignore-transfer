# Snyk Ignore Transfer Tool

A comprehensive tool for transferring ignore rules from CSV data to Snyk issues. Features class-based architecture, enhanced error handling, and detailed reporting capabilities.

> **Note:** This repository is closed to public contributions.

## 🚀 Key Features

- **Class-based architecture** - Clean, maintainable code structure
- **Enhanced error handling** - Comprehensive validation and user feedback
- **Improved logging** - Structured logging system with different levels
- **Streamlined workflows** - Simplified execution paths
- **Better validation** - Input sanitization and argument validation
- **Customer-ready** - Professional code suitable for distribution
- **Text report generation** - Detailed severity and organization reports
- **Group processing** - Process all organizations in a Snyk group
- **Smart conflict handling** - Treat existing policies as success

## 📋 Features

- **Multiple Workflows**: Standard matching, direct ignore, matches input, group processing
- **Flexible Input**: CSV files or pre-generated matches
- **Smart Matching**: Title + Repository URL + CWE matching
- **Dry Run Support**: Test operations without making changes
- **Comprehensive Logging**: Detailed progress and error reporting
- **Error Recovery**: Graceful handling of API failures and missing data
- **Severity Reports**: Generate detailed text reports of issues by severity and organization
- **Group Processing**: Process all organizations in a Snyk group with pagination
- **Conflict Resolution**: Automatically handle existing policies (409 conflicts)
- **GitHub Integration**: Fetch and parse configuration files from GitHub repositories (optional)

## 🛠️ Installation

### Prerequisites

- Python 3.10+
- Snyk API token

### Setup

1. **Clone or download the tool**:
   ```bash
   # Download the main script
   wget https://raw.githubusercontent.com/your-repo/snyk-ignore-transfer/main/snyk_ignore_transfer.py
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   # Or manually:
   pip install requests pandas PyGithub
   ```

3. **Set up environment variables**:
   ```bash
   export SNYK_TOKEN="your_snyk_api_token"
   ```

## 🎯 Usage

### Basic Usage

```bash
# Standard workflow (match and ignore)
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv

# Dry run to test
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --dry-run

# Direct ignore mode (skip CSV generation)
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --direct-ignore
```

### Advanced Usage

```bash
# Group processing (process all organizations in a group)
python3 snyk_ignore_transfer.py --group-id YOUR_GROUP_ID --csv-file issues.csv --dry-run
python3 snyk_ignore_transfer.py --group-id YOUR_GROUP_ID --csv-file issues.csv

# Review-only mode (generate CSV for review)
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --review-only

# Load pre-generated matches
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --matches-input snyk_matches_20240101_120000.csv

# Generate severity report
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --severity-report report.txt

# Custom configuration
python3 snyk_ignore_transfer.py \
  --org-id YOUR_ORG_ID \
  --csv-file issues.csv \
  --snyk-region SNYK-EU-01 \
  --ignore-reason "Custom reason for ignoring" \
  --repo-url-field custom_repourl_field

# GitHub integration (fetch repository configuration files)
export GITHUB_TOKEN="your_github_token"
python3 snyk_ignore_transfer.py \
  --org-id YOUR_ORG_ID \
  --csv-file issues.csv \
  --github-properties-file appsec.properties \
  --github-property-name app.version
```

## 📊 Workflow Examples

### 1. Standard Matching Workflow
```bash
# Step 1: Generate matches for review
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --review-only

# Step 2: Review the generated CSV file
# Edit snyk_matches_YYYYMMDD_HHMMSS.csv as needed

# Step 3: Process the matches
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --matches-input snyk_matches_20240101_120000.csv
```

### 2. Direct Ignore Workflow
```bash
# Skip CSV generation and go directly to ignoring
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --direct-ignore
```

### 3. Group Processing Workflow
```bash
# Process all organizations in a Snyk group
python3 snyk_ignore_transfer.py --group-id YOUR_GROUP_ID --csv-file issues.csv --dry-run
python3 snyk_ignore_transfer.py --group-id YOUR_GROUP_ID --csv-file issues.csv
```

### 4. Generate Severity Report
```bash
# Generate detailed severity and organization report
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --severity-report report.txt
```

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Snyk API token for authentication |
| `GITHUB_TOKEN` | No | GitHub personal access token for repository access (optional) |

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--org-id` | Snyk organization ID | Required (or use --group-id) |
| `--group-id` | Snyk group ID to process all orgs | Alternative to --org-id |
| `--csv-file` | CSV file with issues to match | Required for normal workflow |
| `--matches-input` | Pre-generated matches CSV | Alternative to --csv-file |
| `--direct-ignore` | Skip CSV generation | False |
| `--review-only` | Generate CSV for review only | False |
| `--dry-run` | Simulate without changes | False |
| `--severity-report` | Generate text report file | Optional |
| `--snyk-region` | Snyk API region | SNYK-US-01 |
| `--ignore-reason` | Reason for ignoring issues | "False positive identified via CSV analysis" |
| `--repo-url-field` | CSV field containing repo URL | repourl |
| `--github-token` | GitHub personal access token | Use GITHUB_TOKEN env var |
| `--github-properties-file` | Properties file to fetch from repos | appsec.properties |
| `--github-property-name` | Specific property to extract | All properties |
| `--df-match` | Use DataFrame matching (faster) | False |

## 📁 File Structure

```
snyk_ignore_transfer.py      # Main tool
README.md                    # This documentation
requirements.txt             # Python dependencies
```

## 🔍 Matching Criteria

The tool matches Snyk issues with CSV data based on:

1. **Line Number** - Must match line number or be within the range
2. **Repository URL** - Must match exactly (if provided in CSV)
3. **CWE** - Must match exactly (normalized format)
4. **False positive check** - Skips CSV rows marked as false positives

## 🛡️ Error Handling

The tool includes comprehensive error handling:

- **Input validation** - Checks all required arguments and data
- **API error recovery** - Graceful handling of Snyk API failures
- **File validation** - Checks CSV file format and required fields
- **Environment validation** - Verifies required environment variables
- **Progress tracking** - Detailed logging of operations and errors

## 📝 Logging

The tool provides structured logging with different levels:

- **Info** - Normal operation progress
- **Warning** - Non-critical issues that don't stop execution
- **Error** - Critical issues that prevent operation
- **Debug** - Detailed debugging information (when --verbose is used)

## 🔄 Workflow Comparison

| Workflow | Use Case | CSV Generation | Best For |
|----------|----------|----------------|----------|
| Standard | Review and approve | Yes | Manual review process |
| Direct Ignore | Automated processing | No | CI/CD pipelines |
| Matches Input | Pre-generated matches | No | Batch processing |
| Group Processing | Multiple organizations | Yes | Enterprise-wide deployment |
| Severity Report | Analysis and reporting | Yes | Documentation and analysis |

## 🚨 Troubleshooting

### Common Issues

1. **Missing SNYK_TOKEN**
   ```
   Error: SNYK_TOKEN environment variable is required
   ```
   **Solution**: Set the environment variable with your Snyk API token

2. **Invalid organization ID**
   ```
   Error: No code issues found in organization
   ```
   **Solution**: Verify the organization ID is correct and has code issues

3. **CSV file not found**
   ```
   Error: CSV file issues.csv not found
   ```
   **Solution**: Check the file path and ensure the file exists

4. **CSV parsing errors**
   ```
   Error: No CSV data loaded
   ```
   **Solution**: Check CSV file format and ensure it contains valid data

### Debug Mode

Use `--verbose` (or `-v`) flag for detailed debugging information to understand why matches aren't being made:

```bash
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --verbose
# Or use the short form:
python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv -v
```

**What Debug Mode Shows:**

The verbose mode provides detailed matching diagnostics including:
- Total number of Snyk issues and CSV false positives being compared
- For each CSV row being matched:
  - The values being searched for (branch, file, CWE, repo URL, line number)
  - Comparison details for each Snyk issue checked
  - Specific reason why each Snyk issue doesn't match (branch mismatch, filename mismatch, CWE mismatch, repo URL mismatch)
  - Confirmation when a match is found with all matching details
- Summary of total matches found

**Example Debug Output:**

```
2024-11-05 10:30:15 - INFO - Verbose mode enabled - detailed debug logging activated
2024-11-05 10:30:15 - DEBUG - Starting matching with 150 Snyk issues and 25 CSV false positives
2024-11-05 10:30:15 - DEBUG - Matching mode: Exact URL
================================================================================
2024-11-05 10:30:15 - DEBUG - CSV row 1 - Looking for matches:
2024-11-05 10:30:15 - DEBUG -   Branch: main
2024-11-05 10:30:15 - DEBUG -   File: app.py (from src/app.py)
2024-11-05 10:30:15 - DEBUG -   CWE: CWE-79
2024-11-05 10:30:15 - DEBUG -   Line: 42
2024-11-05 10:30:15 - DEBUG -   Repo URL: https://github.com/myorg/myrepo
2024-11-05 10:30:15 - DEBUG -   Snyk issue 1: Branch mismatch (Snyk: 'develop' vs CSV: 'main')
2024-11-05 10:30:15 - DEBUG -   Snyk issue 2: Filename mismatch (Snyk: 'test.py' vs CSV: 'app.py')
2024-11-05 10:30:15 - DEBUG -   Snyk issue 3: CWE mismatch (Snyk: 'CWE-89' vs CSV: 'CWE-79')
2024-11-05 10:30:15 - DEBUG -   ✅ MATCH FOUND with Snyk issue!
2024-11-05 10:30:15 - DEBUG -      Snyk URL: https://github.com/myorg/myrepo
2024-11-05 10:30:15 - DEBUG -      Snyk File Path: src/app.py
2024-11-05 10:30:15 - DEBUG -      Snyk Line Range: 40-45
2024-11-05 10:30:15 - DEBUG -      Line match: CSV line 42 is within Snyk range
```

This detailed output helps you quickly identify:
- Data format issues in your CSV (missing fields, wrong format)
- Mismatches in branch names, file paths, or CWE identifiers
- Repository URL discrepancies
- Line number alignment problems

## 🔗 GitHub Integration

The tool now supports optional GitHub integration to fetch and parse configuration files from your repositories. This allows you to enrich issue data with properties from files like `appsec.properties`.

### Quick Start

1. **Get a GitHub Token**: Create a personal access token at [GitHub Settings](https://github.com/settings/tokens)
   - Scopes needed: `repo` (or `public_repo` for public repos only)

2. **Set the Token**:
   ```bash
   export GITHUB_TOKEN="your_github_token_here"
   ```

3. **Use GitHub Integration**:
   ```bash
   python3 snyk_ignore_transfer.py \
     --org-id YOUR_ORG_ID \
     --csv-file issues.csv \
     --github-properties-file appsec.properties \
     --github-property-name app.version
   ```

### Features

- **File Fetching**: Read any file from GitHub repositories
- **Properties Parsing**: Parse Java properties files (key=value format)
- **Smart Branch Matching**: Tries to match the branch Snyk scanned
- **Caching**: Minimizes API calls to avoid rate limits
- **Flexible URLs**: Supports HTTPS and SSH GitHub URLs

### Documentation

For detailed information about GitHub integration, see [GITHUB_INTEGRATION.md](GITHUB_INTEGRATION.md).

For testing GitHub integration, run:
```bash
python3 test_github_integration.py
```

## 📞 Support

For issues and questions:

- Check this documentation first
- Review the error messages and troubleshooting section
- Open an issue on GitHub with detailed error information
- Include the command used and any relevant log output

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request
