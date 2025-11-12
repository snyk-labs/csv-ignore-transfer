# List Ignore Policies

A companion script to surface and report on ignore policies created by the `snyk_ignore_transfer.py` tool.

## Overview

This script queries Snyk organizations to find ignore policies created by the ignore transfer tool. It searches for policies by their ignore reason and generates detailed CSV reports showing which issues have been ignored.

## Features

- ✅ Query single organization or entire group
- ✅ Search by custom ignore reason (defaults to transfer tool's reason)
- ✅ Export detailed policy information to CSV
- ✅ Console summary with statistics

## Prerequisites

- Python 3.7+
- `requests` library
- `snyk_ignore_transfer.py` (must be in the same directory)
- Valid Snyk API token with appropriate permissions

## Environment Variables

```bash
export SNYK_TOKEN="your-snyk-api-token"
export SNYK_GROUP_ID="your-group-id"  # Optional, for group queries
```

## Usage

### Basic Usage - Single Organization

```bash
python3 list_ignore_policies.py --org-id YOUR_ORG_ID
```

### Query Entire Group

```bash
python3 list_ignore_policies.py --group-id YOUR_GROUP_ID
```

Or use your environment variable:

```bash
python3 list_ignore_policies.py --group-id $SNYK_GROUP_ID
```

### Custom Ignore Reason

Search for policies with a specific ignore reason:

```bash
python3 list_ignore_policies.py --org-id YOUR_ORG_ID --ignore-reason "testing cci ignore"
```

### Export to CSV

```bash
python3 list_ignore_policies.py --org-id YOUR_ORG_ID --output policies.csv
```

### Combined Example

```bash
python3 list_ignore_policies.py \
  --group-id $SNYK_GROUP_ID \
  --ignore-reason "False positive identified via CSV analysis" \
  --output all_policies.csv
```

## Command-Line Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `--org-id` | Snyk organization ID | Either this or `--group-id` | - |
| `--group-id` | Snyk group ID (processes all orgs) | Either this or `--org-id` | - |
| `--ignore-reason` | Ignore reason to search for (partial match) | No | `"False positive identified via CSV analysis"` |
| `--snyk-region` | Snyk API region | No | `SNYK-US-01` |
| `--output` | Output CSV file path | No | - |

## Output Format

### Console Output

The script provides a summary including:
- Organization name
- Ignore reason being searched
- Total policies found
- Breakdown by ignore type
- Date range (first/last created)

Example:

```
================================================================================
📊 IGNORE POLICIES SUMMARY
================================================================================
Organization: Single Organization
Ignore Reason: "False positive identified via CSV analysis"
Total Ignore Policies: 8

📊 By Ignore Type:
   not-vulnerable: 8

📅 Date Range:
   First created: 2025-11-10
   Last created: 2025-11-10

================================================================================
```

### CSV Output

The CSV file contains the following columns:

| Column | Description |
|--------|-------------|
| `policy_id` | Unique policy identifier |
| `policy_name` | Human-readable policy name |
| `action_type` | Action type (typically "ignore") |
| `ignore_type` | Type of ignore (e.g., "not-vulnerable") |
| `reason` | Full ignore reason text |
| `key_asset` | **Snyk issue ID being ignored** (most important!) |
| `created_at` | ISO timestamp when policy was created |
| `updated_at` | ISO timestamp of last update |
| `created_by_name` | Name of user who created the policy |
| `created_by_email` | Email of user who created the policy |


## Examples

### Example 1: Find All Default Ignores in an Organization

```bash
python3 list_ignore_policies.py --org-id b39a8a2e-ecaf-4362-95a9-98e4ace62e13
```

### Example 2: Group-Wide Audit with CSV Export

```bash
python3 list_ignore_policies.py \
  --group-id $SNYK_GROUP_ID \
  --output group_ignores.csv
```

This creates separate CSV files for each organization with policies.

### Example 3: Find Custom Ignore Reason

```bash
python3 list_ignore_policies.py \
  --org-id YOUR_ORG_ID \
  --ignore-reason "Security team approved" \
  --output approved_ignores.csv
```

## Group Processing

When using `--group-id`, the script will:

1. Fetch all organizations in the group
2. Process each organization sequentially
3. Show progress: `[5/266] Processing: org-name`
4. Skip organizations with no policies
5. Generate org-specific CSV files (if `--output` is specified)
6. Display a group summary at the end

Example group summary:

```
================================================================================
📊 GROUP SUMMARY
================================================================================
Total Organizations: 266
Total Ignore Policies: 29
Breakdown by Organization:
   Customer Success: 7
   code consistent ignores demo: 12
   Team Alpha: 4
   Team Beta: 3
================================================================================
```

## See Also

- [Main README](README.md) - Full project documentation
- [snyk_ignore_transfer.py](snyk_ignore_transfer.py) - The ignore transfer tool
- [Snyk API Documentation](https://docs.snyk.io/snyk-api) - Official API reference

