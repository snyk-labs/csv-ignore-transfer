#!/usr/bin/env python3
"""
Snyk Ignore Transfer Tool

This script pulls all Snyk code issues for an organization, compares them with
data from a CSV file, and ignores matched issues in Snyk.

Usage:
    python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv
    python3 snyk_ignore_transfer.py --org-id YOUR_ORG_ID --csv-file issues.csv --dry-run
"""

import json
import argparse
import sys
import os
import csv
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Constants for better maintainability
PROGRESS_BATCH_SIZE = 100  # Progress update frequency
API_BATCH_SIZE = 100      # API pagination batch size
TITLE_TRUNCATE_LENGTH = 100  # Max length for titles in reports
ISSUE_TITLE_DISPLAY_LENGTH = 50  # Max length for issue titles in progress


class Config:
    """Configuration class for centralized settings management."""
    
    # API Settings
    DEFAULT_API_VERSION = "2024-10-15"
    ISSUE_DETAIL_API_VERSION = "2024-10-14~experimental"
    POLICY_API_VERSION = "2024-10-15"
    
    # Matching Settings
    SIMILARITY_THRESHOLD = 0.6  # Jaccard similarity threshold for title matching
    
    # Report Settings
    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'unknown']
    
    # Default Values
    DEFAULT_REGION = "SNYK-US-01"
    DEFAULT_IGNORE_REASON = "False positive identified via CSV analysis"
    DEFAULT_REPO_URL_FIELD = "repourl"


class SnykAPI:
    """Snyk API client for managing issues and ignores."""

    def __init__(self, token: str, region: str = "SNYK-US-01"):
        self.token = token
        self.base_url = self._get_base_url(region)
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {token}',
            'Accept': '*/*'
        })

    def _get_base_url(self, region: str) -> str:
        """Get the appropriate API base URL for the region."""
        region_urls = {
            "SNYK-US-01": "https://api.snyk.io",
            "SNYK-US-02": "https://api.us.snyk.io",
            "SNYK-EU-01": "https://api.eu.snyk.io",
            "SNYK-AU-01": "https://api.au.snyk.io"
        }
        return region_urls.get(region, "https://api.snyk.io")

    def get_all_orgs_from_group(self, group_id: str, version: str = "2024-10-15") -> List[Dict]:
        """
        Fetch all organizations from a Snyk group.

        Args:
            group_id: Group ID
            version: API version

        Returns:
            List of organization data
        """
        all_orgs = []
        next_url = None
        
        print(f"🔍 Fetching all organizations for group {group_id}...")
        
        while True:
            if next_url:
                url = next_url
            else:
                url = f"{self.base_url}/rest/groups/{group_id}/orgs"
                params = {
                    'limit': API_BATCH_SIZE,
                    'version': version
                }
            
            try:
                if next_url:
                    # Handle relative URLs by prepending base URL
                    if next_url.startswith('/'):
                        url = f"{self.base_url}{next_url}"
                    else:
                        url = next_url
                    response = self.session.get(url)
                else:
                    response = self.session.get(url, params=params)
                
                response.raise_for_status()
                data = response.json()
                
                orgs = data.get('data', [])
                all_orgs.extend(orgs)
                
                print(f"   📄 Fetched {len(orgs)} organizations (total: {len(all_orgs)})")
                
                # Check for next page
                links = data.get('links', {})
                next_url = links.get('next')
                
                if not next_url:
                    break
                    
            except requests.exceptions.RequestException as e:
                print(f"   ❌ Error fetching organizations: {e}")
                break
        
        print(f"   ✅ Found {len(all_orgs)} total organizations")
        return all_orgs

    def get_all_code_issues(self, org_id: str, version: str = "2024-10-15") -> List[Dict]:
        """
        Get all code issues for a Snyk organization, handling pagination.

        Args:
            org_id: Organization ID
            version: API version

        Returns:
            List of all code issues with their complete data
        """
        url = f"{self.base_url}/rest/orgs/{org_id}/issues"
        params = {
            'version': version,
            'type': 'code',
            'limit': API_BATCH_SIZE,
            'status': 'open'
        }

        all_issues = []
        next_url = url
        next_params = params
        page = 1

        while next_url:
            print(f"   📄 Fetching page {page}...")
            response = self.session.get(next_url, params=next_params)
            response.raise_for_status()
            data = response.json()

            issues = data.get('data', [])
            all_issues.extend(issues)

            # Handle pagination
            links = data.get('links', {})
            next_url = links.get('next')
            next_params = None

            if next_url:
                if next_url.startswith('http'):
                    pass  # use as-is
                elif next_url.startswith('/'):
                    next_url = self.base_url + next_url
                else:
                    next_url = self.base_url + '/' + next_url.lstrip('/')
            else:
                next_url = None

            page += 1

        print(f"   ✅ Found {len(all_issues)} total code issues")
        return all_issues

    def get_targets_for_org(self, org_id: str, version: str = "2024-10-15") -> List[Dict]:
        """
        Get all targets for a Snyk organization to preserve attributes.url.

        Args:
            org_id: Organization ID
            version: API version

        Returns:
            List of all targets with their URLs and metadata
        """
        url = f"{self.base_url}/rest/orgs/{org_id}/targets"
        params = {
            'version': version,
            'limit': 100
        }

        all_targets = []
        next_url = url
        next_params = params
        page = 1

        while next_url:
            print(f"   📄 Fetching targets page {page}...")
            response = self.session.get(next_url, params=next_params)
            response.raise_for_status()
            data = response.json()

            targets = data.get('data', [])
            all_targets.extend(targets)

            # Handle pagination
            links = data.get('links', {})
            next_url = links.get('next')
            next_params = None

            if next_url:
                if next_url.startswith('http'):
                    pass  # use as-is
                elif next_url.startswith('/'):
                    next_url = self.base_url + next_url
                else:
                    next_url = self.base_url + '/' + next_url.lstrip('/')
            else:
                next_url = None

            page += 1

        print(f"   ✅ Found {len(all_targets)} total targets")
        return all_targets

    def get_issue_details(self, org_id: str, project_id: str, issue_id: str,
                         version: str = "2024-10-14~experimental") -> Optional[Dict]:
        """
        Fetch detailed information for a specific code issue.

        Args:
            org_id: Organization ID
            project_id: Project ID (scan_item)
            issue_id: Issue problem ID
            version: API version for issue details

        Returns:
            Dictionary containing the issue details or None if failed
        """
        url = f"{self.base_url}/rest/orgs/{org_id}/issues/detail/code/{issue_id}"
        params = {
            'project_id': project_id,
            'version': version
        }

        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Error fetching issue details for {issue_id}: {e}")
            return None

    def get_project_details(self, org_id: str, project_id: str, version: str = "2024-10-15") -> Optional[Dict]:
        """
        Fetch detailed information for a specific project, including branch information.

        Args:
            org_id: Organization ID
            project_id: Project ID
            version: API version for project details

        Returns:
            Dictionary containing the project details or None if failed
        """
        url = f"{self.base_url}/rest/orgs/{org_id}/projects/{project_id}"
        params = {
            'version': version
        }

        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Error fetching project details for {project_id}: {e}")
            return None

    def create_ignore_policy(self, org_id: str, key_asset: str, reason: str = "Not relevant", 
                           cwe: str = "", title: str = "", dry_run: bool = False) -> bool:
        """
        Create an ignore policy using the REST API policy endpoint for Snyk Code issues.
        
        Args:
            org_id: Organization ID
            key_asset: The key_asset value from the issue attributes
            reason: Reason for ignoring
            cwe: CWE number for naming
            title: Issue title for naming
            dry_run: If True, don't actually create the policy
            
        Returns:
            bool: True if successful, False otherwise
        """
        if dry_run:
            print(f"   🏃‍♂️ DRY RUN: Would create ignore policy for key_asset {key_asset}")
            return True
            
        url = f"{self.base_url}/rest/orgs/{org_id}/policies?version=2024-10-15"
        
        # Create policy name - format should match the existing ignore reason pattern
        policy_name = f"Consistent Ignore - Converted"
        if cwe and title:
            policy_name += f" CWE: {cwe}, CSV Title: {title[:100]}"
        
        data = {
            "data": {
                "attributes": {
                    "action": {
                        "data": {
                            "ignore_type": "not-vulnerable",
                            "reason": reason
                        }
                    },
                    "action_type": "ignore",
                    "conditions_group": {
                        "conditions": [
                            {
                                "field": "snyk/asset/finding/v1",
                                "operator": "includes",
                                "value": key_asset
                            }
                        ],
                        "logical_operator": "and"
                    },
                    "name": policy_name
                },
                "type": "policy"
            }
        }
        
        try:
            print(f"   🔗 API URL: {url}")
            print(f"   📤 Request data: {json.dumps(data, indent=2)}")
            
            response = self.session.post(url, json=data, headers={"Content-Type": "application/vnd.api+json"})
            
            print(f"   📥 Response status: {response.status_code}")
            print(f"   📥 Response body: {response.text}")
            
            response.raise_for_status()
            print(f"   ✅ Successfully created ignore policy for key_asset {key_asset}")
            return True
        except requests.exceptions.RequestException as e:
            error_details = ""
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = f" - Response: {e.response.text}"
                    # Handle 409 conflict - policy already exists
                    if e.response.status_code == 409:
                        print(f"   ✅ Policy already exists for key_asset {key_asset} (409 Conflict)")
                        return True
                except:
                    pass
            print(f"   ❌ Error creating ignore policy for key_asset {key_asset}: {e}{error_details}")
            return False

    def ignore_issue(self, org_id: str, project_id: str, issue_id: str,
                     reason: str = "Not relevant", reason_type: str = "not-vulnerable",
                     disregard_if_fixable: bool = False, expires: str = "",
                     dry_run: bool = False) -> bool:
        """
        Ignore a specific issue in Snyk.

        Args:
            org_id: Organization ID
            project_id: Project ID
            issue_id: Issue ID to ignore
            reason: Reason for ignoring the issue
            reason_type: Snyk reason type not-vulnerable, wont-fix, and temporary-ignore
            disregard_if_fixable: If True, the issue will be not be ignored if it is fixable
            dry_run: If True, only simulate the action

        Returns:
            True if successful, False otherwise
        """
        if dry_run:
            print(f"   🏃‍♂️ DRY RUN: Would ignore issue {issue_id} with reason: {reason}")
            return True

        url = f"{self.base_url}/v1/org/{org_id}/project/{project_id}/ignore/{issue_id}"
        data = {
            "ignorePath": "",
            "reason": reason,
            "reasonType": reason_type,
            "disregardIfFixable": disregard_if_fixable
        }
        
        # Only add expires if it's provided and not empty
        if expires and expires.strip():
            data["expires"] = expires

        try:
            print(f"   🔗 API URL: {url}")
            print(f"   📤 Request data: {json.dumps(data, indent=2)}")
            
            response = self.session.post(url, json=data)
            
            print(f"   📥 Response status: {response.status_code}")
            print(f"   📥 Response body: {response.text}")
            
            response.raise_for_status()
            print(f"   ✅ Successfully ignored issue {issue_id}")
            return True
        except requests.exceptions.RequestException as e:
            error_details = ""
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = f" - Response: {e.response.text}"
                except:
                    pass
            print(f"   ❌ Error ignoring issue {issue_id}: {e}{error_details}")
            return False


class IssueProcessor:
    """Process and enrich Snyk issues with target information."""

    def __init__(self, snyk_api: SnykAPI):
        self.snyk_api = snyk_api
        self.targets_cache = {}
        self.cwe_mapping = self._build_cwe_mapping()

    @staticmethod
    def create_processing_summary(matches: List, results: Dict = None, is_group: bool = False, 
                                group_stats: Dict = None) -> Dict:
        """
        Create a standardized processing summary dictionary.
        
        Args:
            matches: List of matches processed
            results: Results dictionary from ignore processing (optional)
            is_group: Whether this is for group processing
            group_stats: Group-level statistics (for group processing)
            
        Returns:
            Dictionary with processing summary
        """
        summary = {
            'total_matches': len(matches) if matches else 0,
            'successful_ignores': results.get('successful_ignores', 0) if results else 0,
            'failed_ignores': results.get('failed_ignores', 0) if results else 0
        }
        
        if is_group and group_stats:
            summary.update({
                'total_orgs': group_stats.get('total_orgs', 0),
                'successful_orgs': group_stats.get('successful_orgs', 0),
                'failed_orgs': group_stats.get('failed_orgs', 0)
            })
            
        return summary

    def enrich_issues_with_targets(self, org_id: str, issues: List[Dict]) -> List[Dict]:
        """
        Enrich issues with target information including attributes.url.

        Args:
            org_id: Organization ID
            issues: List of issues to enrich

        Returns:
            List of enriched issues with target information
        """
        # Get all targets for the organization
        targets = self.snyk_api.get_targets_for_org(org_id)

        # Create a lookup dictionary for targets by ID
        targets_lookup = {}
        for target in targets:
            target_id = target.get('id')
            if target_id:
                targets_lookup[target_id] = {
                    'url': target.get('attributes', {}).get('url'),
                    'display_name': target.get('attributes', {}).get('display_name'),
                    'origin': target.get('attributes', {}).get('origin'),
                    'target_data': target
                }

        # OPTIMIZATION: Cache project details to avoid duplicate API calls
        project_cache = {}

        enriched_issues = []

        for i, issue in enumerate(issues):
            if i % PROGRESS_BATCH_SIZE == 0:  # Progress indicator
                print(f"   📦 Processing issue {i+1}/{len(issues)}...")
            
            # Create a copy of the issue
            enriched_issue = issue.copy()

            # Get project ID from scan_item relationships
            relationships = issue.get('relationships', {})
            scan_item_data = relationships.get('scan_item', {}).get('data', {})
            project_id = scan_item_data.get('id')

            # Get target ID from project details (with caching)
            target_id = None
            if project_id:
                if project_id in project_cache:
                    # Use cached data
                    target_id = project_cache[project_id]
                else:
                    # Make API call and cache result
                    try:
                        project_details = self.snyk_api.get_project_details(org_id, project_id)
                        project_data = project_details.get('data', {})
                        project_relationships = project_data.get('relationships', {})
                        target_data = project_relationships.get('target', {}).get('data', {})
                        target_id = target_data.get('id')
                        
                        # Cache the result
                        project_cache[project_id] = target_id
                    except Exception as e:
                        print(f"   ⚠️  Warning: Could not get target ID for project {project_id}: {e}")
                        project_cache[project_id] = None  # Cache the failure too

            # Add target information if available
            if target_id and target_id in targets_lookup:
                target_info = targets_lookup[target_id]
                enriched_issue['target_info'] = {
                    'target_id': target_id,
                    'url': target_info['url'],
                    'display_name': target_info['display_name'],
                    'origin': target_info['origin']
                }
            else:
                enriched_issue['target_info'] = {
                    'target_id': target_id,
                    'url': None,
                    'display_name': None,
                    'origin': None
                }

            enriched_issues.append(enriched_issue)
        return enriched_issues

    def extract_issue_key_data(self, issue: Dict) -> Dict:
        """
        Extract key data from an issue for comparison and processing.
        Fetches detailed issue information to get file path and line numbers.

        Args:
            issue: Enriched issue dictionary

        Returns:
            Dictionary with key issue data for matching
        """
        attributes = issue.get('attributes', {})
        relationships = issue.get('relationships', {})
        target_info = issue.get('target_info', {})

        # Extract basic identifiers
        org_id = relationships.get('organization', {}).get('data', {}).get('id')
        project_id = relationships.get('scan_item', {}).get('data', {}).get('id')

        # Extract problem_id from problems array (used for issue details API)
        problem_id = None
        problems = attributes.get('problems', [])
        if problems and isinstance(problems, list) and len(problems) > 0:
            first_problem = problems[0]
            if isinstance(first_problem, dict):
                problem_id = first_problem.get('id')

        # Extract CWE from classes field
        cwe = None
        classes = attributes.get('classes', [])
        for cls in classes:
            if isinstance(cls, dict) and cls.get('source') == 'CWE':
                cwe = cls.get('id')  # Should be like "CWE-78"
                break

        # Fetch issue details to get file path and line information
        file_path = None
        start_line = None
        end_line = None

        if org_id and project_id and problem_id:
            details = self.snyk_api.get_issue_details(org_id, project_id, problem_id)
            if details:
                detail_attrs = details.get('data', {}).get('attributes', {})
                file_path = detail_attrs.get('primaryFilePath')

                primary_region = detail_attrs.get('primaryRegion', {})
                if primary_region:
                    start_line = primary_region.get('startLine')
                    end_line = primary_region.get('endLine')

        # Fetch project details to get branch information
        branch = None
        target_reference = None

        if org_id and project_id:
            project_details = self.snyk_api.get_project_details(org_id, project_id)
            if project_details:
                project_attrs = project_details.get('data', {}).get('attributes', {})
                target_reference = project_attrs.get('target_reference')
                branch = target_reference
            else:
                print(f"   ❌ Error fetching project details for {project_id}: {project_details}")

        # Extract issue_id and handle None case
        issue_id = issue.get('id')
        if issue_id is None:
            print(f"   ⚠️  Warning: Issue missing ID field - skipping: {attributes.get('title', 'Unknown')[:ISSUE_TITLE_DISPLAY_LENGTH]}...")
            return None  # Return None to indicate this issue should be skipped

        return {
            'issue_id': issue_id,
            'key': attributes.get('key'),
            'title': attributes.get('title'),
            'severity': attributes.get('effective_severity_level'),
            'target_url': target_info.get('url'),
            'target_display_name': target_info.get('display_name'),
            'project_id': project_id,
            'org_id': org_id,
            'problem_id': problem_id,
            'file_path': file_path,
            'start_line': start_line,
            'end_line': end_line,
            'line_number': start_line,  # Use start_line for compatibility
            'branch': branch,
            'target_reference': target_reference,
            'cwe': cwe,
            'created_at': attributes.get('created_at'),
            'updated_at': attributes.get('updated_at'),
            'status': attributes.get('status'),
            'type': attributes.get('type'),
            'raw_attributes': attributes  # Include raw attributes for debugging
        }

    def _build_cwe_mapping(self) -> Dict[str, str]:
        """
        Build a mapping of common Snyk issue patterns to CWE identifiers.
        This can be expanded based on your specific needs.
        """
        return {
            'sql injection': 'CWE-89',
            'cross-site scripting': 'CWE-79',
            'xss': 'CWE-79',
            'path traversal': 'CWE-22',
            'code injection': 'CWE-94',
            'command injection': 'CWE-78',
            'ldap injection': 'CWE-90',
            'xpath injection': 'CWE-643',
            'xml injection': 'CWE-91',
            'buffer overflow': 'CWE-120',
            'use after free': 'CWE-416',
            'null pointer dereference': 'CWE-476',
            'race condition': 'CWE-362',
            'improper authentication': 'CWE-287',
            'missing authorization': 'CWE-862',
            'weak cryptography': 'CWE-327',
            'hardcoded credentials': 'CWE-798',
            'insecure random': 'CWE-330',
            'open redirect': 'CWE-601'
        }

    def _normalize_cwe(self, cwe_value) -> Optional[str]:
        """
        Normalize CWE value to standard format (CWE-XXX).
        Handles both string and numeric inputs from CSV.
        """
        if not cwe_value:
            return None

        # If it's already a string starting with CWE-, return as-is
        if isinstance(cwe_value, str) and cwe_value.startswith('CWE-'):
            return cwe_value

        # Handle numeric values (like 798.0 from CSV)
        if isinstance(cwe_value, (int, float)):
            return f"CWE-{int(cwe_value)}"

        # Handle string numeric values
        if isinstance(cwe_value, str):
            try:
                return f"CWE-{int(float(cwe_value))}"
            except ValueError:
                return None

        return None

    def _extract_filename(self, file_path: str) -> Optional[str]:
        """
        Extract filename from file path (everything after the last "/").

        Args:
            file_path: Full file path like "routes/profileImageUrlUpload.js"

        Returns:
            Filename like "profileImageUrlUpload.js" or None if invalid
        """
        if not file_path:
            return None

        # Handle both forward and backward slashes
        filename = file_path.replace('\\', '/').split('/')[-1]
        return filename.strip() if filename.strip() else None

    def _safe_float_to_int(self, value) -> Optional[int]:
        """
        Safely convert a value to integer, handling floats like 51.0.

        Args:
            value: Value to convert (could be int, float, string, etc.)

        Returns:
            Integer value or None if conversion fails
        """
        if value is None:
            return None

        try:
            if isinstance(value, (int, float)):
                return int(value)
            elif isinstance(value, str):
                return int(float(value.strip()))
        except (ValueError, AttributeError):
            pass

        return None

    def match_issues_with_csv(self, processed_issues: List[Dict], csv_data: List[Dict],
                             repo_url_field: str = 'repourl') -> List[Tuple[Dict, Dict]]:
        """
        Match Snyk issues with CSV data based on Branch + File name + CWE + Line range.

        Matching Criteria:
        - Branch: Must match exactly
        - File name: Extract filename after last "/" - must match exactly
        - CWE: Must match exactly (normalize CSV values)
        - Line numbers: Optional - CSV line within Snyk's start_line to end_line range

        Args:
            processed_issues: List of processed Snyk issues
            csv_data: List of CSV row dictionaries
            repo_url_field: Name of the field containing repo URL in CSV

        Returns:
            List of tuples (snyk_issue, csv_row) for matched items
        """
        # Filter CSV data to only include false positives
        false_positives = [row for row in csv_data if self._is_false_positive(row)]
        print(f"   📋 Found {len(false_positives)} false positive entries in CSV")

        matches = []

        for csv_row in false_positives:
            # Extract CSV matching fields with safe string conversion
            csv_branch = self._safe_str(csv_row.get('branch', ''))
            csv_file_path = self._safe_str(csv_row.get('file_path', ''))
            csv_cwe = self._normalize_cwe(csv_row.get('cwe'))
            csv_line = self._safe_float_to_int(csv_row.get('line'))

            # Skip if missing required fields
            if not csv_branch or not csv_file_path or not csv_cwe:
                continue

            # Extract filename from CSV file path
            csv_filename = self._extract_filename(csv_file_path)
            if not csv_filename:
                continue

            # Extract CSV repository URL
            csv_repo_url = self._safe_str(csv_row.get(repo_url_field, ''))

            for processed_issue in processed_issues:
                issue_data = processed_issue['key_data']

                # Extract Snyk matching fields with safe string conversion
                snyk_branch = self._safe_str(issue_data.get('branch', ''))
                snyk_file_path = self._safe_str(issue_data.get('file_path', ''))
                snyk_cwe = self._safe_str(issue_data.get('cwe', ''))
                snyk_target_url = self._safe_str(issue_data.get('target_url', ''))
                snyk_start_line = issue_data.get('start_line')
                snyk_end_line = issue_data.get('end_line')

                # Skip if missing required fields
                if not snyk_branch or not snyk_file_path or not snyk_cwe or not snyk_target_url:
                    continue

                # Extract filename from Snyk file path
                snyk_filename = self._extract_filename(snyk_file_path)
                if not snyk_filename:
                    continue

                # Required Match 1: Branch must match exactly
                if snyk_branch != csv_branch:
                    continue

                # Required Match 2: File name must match exactly
                if snyk_filename != csv_filename:
                    continue

                # Required Match 3: CWE must match exactly
                if snyk_cwe != csv_cwe:
                    continue

                # Required Match 4: Repository URL must match exactly
                if csv_repo_url and snyk_target_url != csv_repo_url:
                    continue

                # Optional Match: Line numbers (CSV line within Snyk range)
                line_match = False
                if csv_line and snyk_start_line and snyk_end_line:
                    if snyk_start_line <= csv_line <= snyk_end_line:
                        line_match = True

                # We have a match!
                matches.append((processed_issue, csv_row))
                line_status = "✅" if line_match else "❓"
                print(f"   ✅ Match found: {csv_filename} | {csv_cwe} | {csv_branch} | Repo: ✅ | Line: {line_status}")
                break  # Move to next CSV row

        return matches

    def _normalize_cwe_df(self, series):
        """Vectorized normalization of CWE values for pandas Series, outputs 'CWE-<int>' or ''"""
        import pandas as pd
        def norm_one(v):
            if v is None or (isinstance(v, float) and pd.isna(v)):
                return ''
            try:
                # Handles 'CWE-79', '79', '79.0'
                return f"CWE-{int(float(str(v).strip().replace('CWE-', '')))}"
            except Exception:
                v2 = str(v).strip().upper()
                return v2 if v2.startswith('CWE-') else ''
        return series.apply(norm_one)

    def _normalize_repo_url(self, url: Optional[str]) -> str:
        """Normalize repository URL for consistent matching."""
        if not url:
            return ''
        try:
            url = str(url).strip().lower()
        except Exception:
            return ''
        # Standardize protocol and strip common prefixes/suffixes
        if url.startswith('http://'):
            url = 'https://' + url[len('http://'):]
        url = url.rstrip('/')
        if url.startswith('www.'):
            url = url[4:]
        return url

    def match_issues_with_csv_df(self, processed_issues: List[Dict], csv_data: List[Dict], repo_url_field: str = 'repourl') -> List[Tuple[Dict, Dict]]:
        """
        Fast DataFrame-based matcher using pandas. Joins on branch, filename, cwe, and repo URL.
        
        This is an alternative to the traditional nested loop approach that should be significantly
        faster for large datasets. Uses the same matching criteria as match_issues_with_csv.
        """
        import pandas as pd

        # 1) Build CSV DataFrame and keep only false positives
        df_csv_raw = pd.DataFrame(csv_data)
        if df_csv_raw.empty:
            return []

        def is_fp(row):
            v = str(row.get('false_p', '')).strip().upper()
            return v in ('TRUE', 'YES', 'Y', '1')
        df_csv = df_csv_raw[df_csv_raw.apply(is_fp, axis=1)].copy()
        if df_csv.empty:
            return []

        # Normalize CSV columns used for keys
        for col in ['branch', 'file_path']:
            if col in df_csv.columns:
                df_csv[col] = df_csv[col].astype(str).str.strip()
            else:
                df_csv[col] = ''
        df_csv['filename'] = df_csv['file_path'].str.replace('\\\\', '/', regex=True).str.split('/').str[-1].str.strip()
        df_csv['cwe'] = self._normalize_cwe_df(df_csv['cwe'] if 'cwe' in df_csv.columns else pd.Series([]))
        df_csv['repourl'] = df_csv.get(repo_url_field) if repo_url_field in df_csv.columns else ''
        if isinstance(df_csv['repourl'], pd.Series):
            df_csv['repourl'] = df_csv['repourl'].astype(str).apply(self._normalize_repo_url)
        else:
            df_csv['repourl'] = ''

        # Optional line as numeric
        def to_int_safe(x):
            try:
                return int(float(x))
            except Exception:
                return pd.NA
        df_csv['csv_line'] = df_csv['line'].apply(to_int_safe) if 'line' in df_csv.columns else pd.Series([pd.NA] * len(df_csv))

        # 2) Build Snyk DataFrame from processed_issues['key_data']
        key_rows = []
        for it in processed_issues:
            kd = it.get('key_data', {})
            fp = kd.get('file_path') or ''
            filename = fp.replace('\\\\', '/').split('/')[-1].strip() if fp else ''
            key_rows.append({
                'issue_id': kd.get('issue_id'),
                'title': kd.get('title'),
                'cwe': kd.get('cwe'),
                'severity': kd.get('severity'),
                'file_path': fp,
                'filename': filename,
                'start_line': kd.get('start_line'),
                'end_line': kd.get('end_line'),
                'branch': kd.get('branch'),
                'project_id': kd.get('project_id'),
                'created_at': kd.get('created_at'),
                'status': kd.get('status'),
                'org_id': kd.get('org_id'),
                'target_url': self._normalize_repo_url(kd.get('target_url')),
            })
        df_issues = pd.DataFrame(key_rows)
        if df_issues.empty:
            return []

        # Normalize keys in Snyk DF
        for col in ['branch', 'filename', 'cwe']:
            if col in df_issues.columns:
                df_issues[col] = df_issues[col].astype(str).str.strip()
        df_issues['target_url'] = df_issues['target_url'].astype(str)

        # 3) Merge on exact keys (same criteria as traditional matcher)
        merged = df_csv.merge(
            df_issues,
            how='inner',
            left_on=['branch', 'filename', 'cwe', 'repourl'],
            right_on=['branch', 'filename', 'cwe', 'target_url'],
            suffixes=('_csv', '_snyk')
        )
        if merged.empty:
            return []

        # 4) Vectorized optional line-range filter (same logic as traditional matcher)
        def as_Int64(s):
            try:
                return s.astype('Int64')
            except Exception:
                return pd.Series([pd.NA] * len(s), dtype='Int64')
        start_i = as_Int64(merged['start_line'])
        end_i = as_Int64(merged['end_line'])
        line_i = as_Int64(merged['csv_line'])
        in_range = line_i.notna() & start_i.notna() & end_i.notna() & (start_i <= line_i) & (line_i <= end_i)
        keep = in_range | (~line_i.notna())  # Keep matches with or without line range
        merged = merged[keep].copy()
        if merged.empty:
            return []

        # 5) Rehydrate matches (convert back to expected format)
        by_issue_id = {it['key_data'].get('issue_id'): it for it in processed_issues}
        matches: List[Tuple[Dict, Dict]] = []
        for _, r in merged.iterrows():
            issue_id = r.get('issue_id')
            processed_issue = by_issue_id.get(issue_id)
            if processed_issue is None:
                # Fallback minimal structure (shouldn't happen, but safety first)
                processed_issue = {
                    'key_data': {
                        'issue_id': r.get('issue_id'),
                        'title': r.get('title_snyk') or r.get('title'),
                        'cwe': r.get('cwe'),
                        'severity': r.get('severity_snyk') or r.get('severity'),
                        'file_path': r.get('file_path_snyk') or r.get('file_path'),
                        'start_line': r.get('start_line'),
                        'end_line': r.get('end_line'),
                        'branch': r.get('branch'),
                        'project_id': r.get('project_id'),
                        'created_at': r.get('created_at'),
                        'status': r.get('status'),
                        'org_id': r.get('org_id'),
                        'target_url': r.get('target_url'),
                    }
                }
            csv_row = {
                'title': r.get('title_csv') or r.get('title'),
                'cwe': r.get('cwe'),
                'severity': r.get('severity_csv') or r.get('severity'),
                'file_path': r.get('file_path_csv') or r.get('file_path'),
                'line': r.get('csv_line'),
                'branch': r.get('branch'),
                'repourl': r.get('repourl'),
                'test_type': r.get('test_type'),
                'date_discovered': r.get('date_discovered'),
                'false_p': 'TRUE'
            }
            matches.append((processed_issue, csv_row))

        return matches

    def _safe_str(self, value) -> str:
        """Safely convert any value to string, handling pandas types."""
        if value is None:
            return ''
        if isinstance(value, bool):
            return str(value).lower()
        return str(value).strip()

    def _is_false_positive(self, csv_row: Dict) -> bool:
        """Check if a CSV row represents a false positive."""
        false_p = csv_row.get('false_p', '')
        
        # Handle both string and boolean values from pandas
        if isinstance(false_p, bool):
            return false_p
        elif isinstance(false_p, str):
            return false_p.strip().lower() in ['true', '1', 'yes', 't']
        else:
            return False

    def _titles_match(self, snyk_title: str, csv_title: str) -> bool:
        """
        Check if titles match using fuzzy matching.
        This can be made more sophisticated based on your needs.
        """
        # Remove common words and normalize
        import re

        # Remove special characters and normalize whitespace
        snyk_clean = re.sub(r'[^\w\s]', ' ', snyk_title.lower()).strip()
        csv_clean = re.sub(r'[^\w\s]', ' ', csv_title.lower()).strip()

        # Split into words
        snyk_words = set(snyk_clean.split())
        csv_words = set(csv_clean.split())

        # Remove common stop words
        stop_words = {'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        snyk_words -= stop_words
        csv_words -= stop_words

        # Check for significant overlap
        if not snyk_words or not csv_words:
            return False

        intersection = snyk_words & csv_words
        union = snyk_words | csv_words

        # Jaccard similarity using config threshold
        similarity = len(intersection) / len(union) if union else 0
        return similarity >= Config.SIMILARITY_THRESHOLD

    def _repo_urls_match(self, snyk_url: Optional[str], csv_url: str) -> bool:
        """Check if repository URLs match."""
        if not snyk_url or not csv_url:
            return True  # Skip repo URL matching if either is missing

        # Normalize URLs by removing protocols, trailing slashes, etc.
        def normalize_url(url: str) -> str:
            import re
            # Remove protocol
            url = re.sub(r'^https?://', '', url.lower())
            # Remove trailing slash
            url = url.rstrip('/')
            # Remove common prefixes like www.
            url = re.sub(r'^www\.', '', url)
            return url

        return normalize_url(snyk_url) == normalize_url(csv_url)

    def generate_severity_report(self, matches: List[Tuple[Dict, Dict]], output_file: str, 
                                is_group_processing: bool = False, processing_summary: Dict = None):
        """
        Generate a severity report for the matches (works for both single org and group processing).

        Args:
            matches: List of (processed_issue, csv_row) tuples
            output_file: Path to output file for the report
            is_group_processing: True if processing multiple organizations in a group
            processing_summary: Dictionary with processing statistics (orgs, successful_ignores, etc.)
        """
        from collections import defaultdict
        from datetime import datetime

        # Group by severity and organization
        severity_org_counts = defaultdict(lambda: defaultdict(int))
        total_issues = len(matches)

        for processed_issue, csv_row in matches:
            issue_data = processed_issue['key_data']
            severity = issue_data.get('severity') or 'Unknown'
            org_id = issue_data.get('org_id', 'Unknown')
            severity_org_counts[severity][org_id] += 1

        # Generate report content with dynamic title
        report_lines = []
        if is_group_processing:
            title = "SNYK IGNORE TRANSFER - SEVERITY AND GROUP REPORT"
        else:
            title = "SNYK IGNORE TRANSFER - SEVERITY AND ORGANIZATION REPORT"
        
        report_lines.append(title)
        report_lines.append("=" * len(title))
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total Issues to be Ignored: {total_issues}")
        
        # Add processing summary if provided
        if processing_summary:
            report_lines.append("")
            report_lines.append("PROCESSING SUMMARY")
            report_lines.append("=" * 18)
            
            if is_group_processing:
                total_orgs = processing_summary.get('total_orgs', 0)
                successful_orgs = processing_summary.get('successful_orgs', 0)
                failed_orgs = processing_summary.get('failed_orgs', 0)
                report_lines.append(f"Total organizations processed: {total_orgs}")
                report_lines.append(f"Successful organizations: {successful_orgs}")
                report_lines.append(f"Failed organizations: {failed_orgs}")
            else:
                report_lines.append("Single organization processing")
            
            total_matches = processing_summary.get('total_matches', 0)
            successful_ignores = processing_summary.get('successful_ignores', 0)
            failed_ignores = processing_summary.get('failed_ignores', 0)
            
            report_lines.append(f"Total matches processed: {total_matches}")
            report_lines.append(f"Successful ignores: {successful_ignores}")
            report_lines.append(f"Failed ignores: {failed_ignores}")
            
            if successful_ignores + failed_ignores > 0:
                success_rate = (successful_ignores / (successful_ignores + failed_ignores)) * 100
                report_lines.append(f"Success rate: {success_rate:.1f}%")
        
        report_lines.append("")

        # Sort severities by priority using config
        sorted_severities = sorted(severity_org_counts.keys(), 
                                 key=lambda x: Config.SEVERITY_ORDER.index(x.lower()) if x and x.lower() in Config.SEVERITY_ORDER else 999)

        for severity in sorted_severities:
            org_counts = severity_org_counts[severity]
            total_for_severity = sum(org_counts.values())
            
            report_lines.append(f"{severity.upper()} ISSUES: {total_for_severity}")
            report_lines.append("-" * 30)
            
            for org_id, count in sorted(org_counts.items(), key=lambda x: x[1], reverse=True):
                report_lines.append(f"  Organization {org_id}: {count} issues")
            
            report_lines.append("")

        # Summary
        report_lines.append("SUMMARY BY SEVERITY")
        report_lines.append("=" * 20)
        for severity in sorted_severities:
            total_for_severity = sum(severity_org_counts[severity].values())
            percentage = (total_for_severity / total_issues * 100) if total_issues > 0 else 0
            report_lines.append(f"{severity.upper()}: {total_for_severity} issues ({percentage:.1f}%)")

        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_lines))
        except Exception as e:
            print(f"   ❌ Error saving severity report: {e}")


def load_csv_data(csv_file: str) -> List[Dict]:
    """
    Load data from CSV file for comparison using pandas for better large file handling.

    Args:
        csv_file: Path to CSV file

    Returns:
        List of dictionaries representing CSV rows
    """
    import pandas as pd

    try:
        # Read CSV with pandas (no field size limits)
        df = pd.read_csv(csv_file)
        
        # Convert to list of dictionaries
        csv_data = df.to_dict('records')

        print(f"   ✅ Loaded {len(csv_data)} rows from CSV")
        return csv_data

    except FileNotFoundError:
        print(f"   ❌ Error: CSV file {csv_file} not found")
        return []
    except Exception as e:
        print(f"   ❌ Error loading CSV file: {e}")
        return []


def save_issues_to_json(issues: List[Dict], filename: str):
    """Save issues data to JSON file for debugging and reference."""
    try:
        with open(filename, 'w') as f:
            json.dump(issues, f, indent=2, default=str)
        print(f"✅ Saved {len(issues)} issues to {filename}")
    except Exception as e:
        print(f"❌ Error saving issues file: {e}")


def save_matches_to_csv(matches: List[Tuple[Dict, Dict]], filename: str):
    """Save matched issues to CSV file for review before ignoring."""
    import csv

    try:
        csv_columns = [
            # Snyk Issue Information
            'snyk_issue_id', 'snyk_title', 'snyk_cwe', 'snyk_severity', 'snyk_file_path',
            'snyk_filename', 'snyk_start_line', 'snyk_end_line', 'snyk_branch', 'snyk_project_id',
            'snyk_created_at', 'snyk_status', 'snyk_repo_name',
            # CSV Match Information
            'csv_title', 'csv_cwe', 'csv_severity', 'csv_file_path', 'csv_filename',
            'csv_line', 'csv_branch', 'csv_repourl', 'csv_test_type', 'csv_date_discovered',
            # Match Analysis
            'filename_match', 'branch_match', 'cwe_match', 'repourl_match', 'line_in_range', 'match_confidence', 'is_match'
        ]

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()

            for processed_issue, csv_row in matches:
                issue_data = processed_issue['key_data']

                # Extract filenames for comparison
                snyk_filename = issue_data.get('file_path', '').split('/')[-1] if issue_data.get('file_path') else ''
                csv_filename = csv_row.get('file_path', '').split('/')[-1] if csv_row.get('file_path') else ''

                # Check line range match
                csv_line = None
                line_in_range = False
                try:
                    csv_line = int(float(csv_row.get('line', 0)))
                    start_line = issue_data.get('start_line')
                    end_line = issue_data.get('end_line')
                    if start_line and end_line and csv_line:
                        line_in_range = start_line <= csv_line <= end_line
                except (ValueError, TypeError):
                    pass

                # Normalize CWE for comparison
                snyk_cwe = issue_data.get('cwe', '')
                csv_cwe_normalized = f"CWE-{int(float(csv_row.get('cwe', 0)))}" if csv_row.get('cwe') else ''

                # Check repository URL match
                snyk_repo_url = (issue_data.get('target_url') or '').strip()
                csv_repo_url = csv_row.get('repourl', '').strip()
                repourl_match = snyk_repo_url == csv_repo_url if csv_repo_url else True

                # Calculate match confidence
                matches_count = 0
                if snyk_filename == csv_filename: matches_count += 1
                if issue_data.get('branch') == csv_row.get('branch'): matches_count += 1
                if snyk_cwe == csv_cwe_normalized: matches_count += 1
                if repourl_match: matches_count += 1
                if line_in_range: matches_count += 1

                match_confidence = f"{matches_count}/5"

                row_data = {
                    # Snyk Issue Information
                    'snyk_issue_id': issue_data.get('issue_id'),
                    'snyk_title': issue_data.get('title'),
                    'snyk_cwe': snyk_cwe,
                    'snyk_severity': issue_data.get('severity'),
                    'snyk_file_path': issue_data.get('file_path'),
                    'snyk_filename': snyk_filename,
                    'snyk_start_line': issue_data.get('start_line'),
                    'snyk_end_line': issue_data.get('end_line'),
                    'snyk_branch': issue_data.get('branch'),
                    'snyk_project_id': issue_data.get('project_id'),
                    'snyk_created_at': issue_data.get('created_at'),
                    'snyk_status': issue_data.get('status'),
                    'snyk_repo_name': issue_data.get('target_url'),

                    # CSV Match Information
                    'csv_title': csv_row.get('title'),
                    'csv_cwe': csv_row.get('cwe'),
                    'csv_severity': csv_row.get('severity'),
                    'csv_file_path': csv_row.get('file_path'),
                    'csv_filename': csv_filename,
                    'csv_line': csv_line,
                    'csv_branch': csv_row.get('branch'),
                    'csv_repourl': csv_row.get('repourl'),
                    'csv_test_type': csv_row.get('test_type'),
                    'csv_date_discovered': csv_row.get('date_discovered'),

                    # Match Analysis
                    'filename_match': snyk_filename == csv_filename,
                    'branch_match': issue_data.get('branch') == csv_row.get('branch'),
                    'cwe_match': snyk_cwe == csv_cwe_normalized,
                    'repourl_match': repourl_match,
                    'line_in_range': line_in_range,
                    'match_confidence': match_confidence,
                    'is_match': True
                }

                writer.writerow(row_data)

        print(f"✅ Saved {len(matches)} matches to {filename}")

    except Exception as e:
        print(f"❌ Error saving matches CSV: {e}")


def load_matches_from_csv(filename: str) -> List[Tuple[Dict, Dict]]:
    """Load matches from a previously generated CSV file using pandas for better large file handling."""
    import pandas as pd

    try:
        print(f"📄 Loading matches from {filename} using pandas...")
        
        # Read CSV with pandas (no field size limits)
        df = pd.read_csv(filename)
        
        matches = []
        
        for _, row in df.iterrows():
            # Convert pandas row to dict
            row_dict = row.to_dict()
            
            # Reconstruct the processed_issue structure
            processed_issue = {
                'key_data': {
                    'issue_id': row_dict.get('snyk_issue_id'),
                    'title': row_dict.get('snyk_title'),
                    'cwe': row_dict.get('snyk_cwe'),
                    'severity': row_dict.get('snyk_severity'),
                    'file_path': row_dict.get('snyk_file_path'),
                    'start_line': int(row_dict['snyk_start_line']) if pd.notna(row_dict.get('snyk_start_line')) else None,
                    'end_line': int(row_dict['snyk_end_line']) if pd.notna(row_dict.get('snyk_end_line')) else None,
                    'branch': row_dict.get('snyk_branch'),
                    'project_id': row_dict.get('snyk_project_id'),
                    'created_at': row_dict.get('snyk_created_at'),
                    'status': row_dict.get('snyk_status'),
                    'org_id': None,  # Will be set from command line args
                    'problem_id': None  # Not needed for ignoring
                },
                'raw_issue': {}  # Not needed for ignoring
            }

            # Reconstruct the CSV row structure
            csv_row = {
                'title': row_dict.get('csv_title'),
                'cwe': row_dict.get('csv_cwe'),
                'severity': row_dict.get('csv_severity'),
                'file_path': row_dict.get('csv_file_path'),
                'line': row_dict.get('csv_line'),
                'branch': row_dict.get('csv_branch'),
                'repourl': row_dict.get('csv_repourl'),
                'test_type': row_dict.get('csv_test_type'),
                'date_discovered': row_dict.get('csv_date_discovered'),
                'false_p': 'TRUE'  # Assume all loaded matches are false positives
            }

            matches.append((processed_issue, csv_row))

        print(f"✅ Loaded {len(matches)} matches from {filename}")
        return matches

    except FileNotFoundError:
        print(f"❌ Error: Matches CSV file {filename} not found")
        return []
    except Exception as e:
        print(f"❌ Error loading matches CSV: {e}")
        return []




def process_matches_and_ignore_policies(snyk_api: SnykAPI, matches: List[Tuple[Dict, Dict]],
                                       dry_run: bool = False, reason: str = "False positive identified via CSV analysis") -> Dict:
    """
    Process matches and create ignore policies using the new REST API policy endpoint.

    Args:
        snyk_api: Snyk API client
        matches: List of (snyk_issue, csv_row) tuples
        dry_run: If True, simulate actions without making changes
        reason: Reason for ignoring the issues

    Returns:
        Dictionary with success/failure counts
    """
    print(f"🎯 Processing {len(matches)} matched issues for policy creation...")

    results = {
        'total_matches': len(matches),
        'successful_ignores': 0,
        'failed_ignores': 0,
        'skipped': 0
    }

    for i, (processed_issue, csv_row) in enumerate(matches, 1):
        issue_data = processed_issue['key_data']
        org_id = issue_data.get('org_id')
        issue_id = issue_data.get('issue_id')
        issue_title = issue_data.get('title', 'Unknown')
        cwe = issue_data.get('cwe', '')

        # Handle None title
        if issue_title is None:
            issue_title = 'Unknown'
        
        print(f"   [{i}/{len(matches)}] Processing issue: {issue_title[:ISSUE_TITLE_DISPLAY_LENGTH]}...")

        # Validate required IDs
        if not org_id or not issue_id:
            print(f"      ⚠️  Skipping: Missing required IDs (org: {org_id}, issue: {issue_id})")
            results['skipped'] += 1
            continue

        # Get key_asset from the raw issue
        raw_issue = processed_issue['raw_issue']
        attributes = raw_issue.get('attributes', {})
        key_asset = attributes.get('key_asset')

        # If key_asset is not available (e.g., from CSV), fetch from issues endpoint
        if not key_asset:
            print(f"      🔍 Fetching issue from issues endpoint to get key_asset...")
            # Fetch all issues and find the specific one by issue_id
            all_issues = snyk_api.get_all_code_issues(org_id)
            for issue in all_issues:
                if issue.get('id') == issue_id:
                    key_asset = issue.get('attributes', {}).get('key_asset')
                    break
            
            if not key_asset:
                print(f"      ⚠️  Skipping: No key_asset found in issue attributes")
                results['skipped'] += 1
                continue

        # Build detailed reason with CSV context
        csv_title = csv_row.get('title', 'Unknown')
        detailed_reason = f"{reason}. CWE: {cwe}, CSV Title: {csv_title[:TITLE_TRUNCATE_LENGTH]}"

        # Create ignore policy
        success = snyk_api.create_ignore_policy(
            org_id=org_id,
            key_asset=key_asset,
            reason=detailed_reason,
            cwe=cwe,
            title=csv_title,
            dry_run=dry_run
        )

        if success:
            results['successful_ignores'] += 1
        else:
            results['failed_ignores'] += 1

    return results


def display_results_summary(results: Dict, dry_run: bool = False):
    """Display a summary of the ignore operation results."""
    action = "DRY RUN - Would ignore" if dry_run else "Ignored"

    print(f"\n📊 {action} Results Summary:")
    print("=" * 40)
    print(f"   📋 Total matches found: {results['total_matches']}")
    print(f"   ✅ Successfully {action.lower()}: {results['successful_ignores']}")
    print(f"   ❌ Failed to ignore: {results['failed_ignores']}")
    print(f"   ⚠️  Skipped (missing data): {results['skipped']}")

    if results['total_matches'] > 0:
        success_rate = (results['successful_ignores'] / results['total_matches']) * 100
        print(f"   📈 Success rate: {success_rate:.1f}%")


def process_single_organization(snyk_api: SnykAPI, args, org_id: str, org_name: str, csv_data: List[Dict] = None, direct_ignore: bool = False, skip_individual_report: bool = False) -> Dict:
    """
    Process a single organization with the current workflow.
    
    Args:
        snyk_api: Snyk API client
        args: Parsed command line arguments
        org_id: Organization ID to process
        org_name: Organization name for display
        csv_data: Pre-loaded CSV data (optional, for group processing efficiency)
        direct_ignore: If True, skip CSV generation and proceed directly to ignoring
        
    Returns:
        Dictionary with processing results
    """
    from datetime import datetime
    
    # Set the org_id for this iteration
    original_org_id = args.org_id
    args.org_id = org_id
    
    try:
        print(f"   🔄 Processing organization: {org_name}")
        
        # Handle matches-input workflow
        if args.matches_input:
            print(f"   📄 Loading matches from: {args.matches_input}")
            matches = load_matches_from_csv(args.matches_input)
            if not matches:
                print(f"   ❌ Error: No matches loaded from CSV file")
                return {'success': False, 'error': 'No matches loaded'}
            
            # Set org_id in all loaded matches
            for processed_issue, csv_row in matches:
                processed_issue['key_data']['org_id'] = org_id
            
            print(f"   ✅ Loaded {len(matches)} matches for processing")
            
            # Process matches and ignore issues
            print(f"   🚫 Processing loaded matches and ignoring issues")
            results = process_matches_and_ignore_policies(
                snyk_api=snyk_api,
                matches=matches,
                dry_run=args.dry_run,
                reason=args.ignore_reason
            )
            
            # Generate severity report (always when ignoring issues, unless skipping for group processing)
            if not skip_individual_report:
                severity_report_file = args.severity_report
                if not severity_report_file:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    severity_report_file = f"snyk_severity_report_{org_name}_{timestamp}.txt"
                
                # Create processing summary for single org
                processing_summary = IssueProcessor.create_processing_summary(matches, results)
                
                processor = IssueProcessor(snyk_api)
                processor.generate_severity_report(matches, severity_report_file, 
                                                     is_group_processing=False, 
                                                     processing_summary=processing_summary)
            
            return {
                'success': True,
                'matches_processed': len(matches),
                'successful_ignores': results['successful_ignores'],
                'failed_ignores': results['failed_ignores'],
                'matches': matches if skip_individual_report else None
            }
        
        # Handle direct-ignore workflow
        elif direct_ignore:
            print("🚀 Direct ignore workflow (skipping CSV generation)")
            print(f"   📄 Using CSV file: {args.csv_file}")
            
            # CSV data should already be loaded and passed in
            if csv_data is None:
                print(f"   ❌ Error: No CSV data provided for direct ignore")
                return {'success': False, 'error': 'No CSV data provided'}
            
            print(f"   ✅ Using pre-loaded CSV data ({len(csv_data)} rows)")
            
            # Initialize issue processor
            processor = IssueProcessor(snyk_api)
            
            # Get all code issues for the organization
            print(f"   🚀 Fetching all code issues for organization {org_id}")
            all_issues = snyk_api.get_all_code_issues(org_id)
            
            if not all_issues:
                print(f"   ℹ️  No code issues found in organization")
                
                # Generate empty report for audit trail (unless skipping for group processing)
                if not skip_individual_report:
                    print(f"   📊 Generating severity and organization report")
                    severity_report_file = args.severity_report
                    if not severity_report_file:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        severity_report_file = f"snyk_severity_report_{org_name}_{timestamp}.txt"
                    
                    # Create processing summary for empty matches
                    processing_summary = IssueProcessor.create_processing_summary([])
                    
                    processor.generate_severity_report([], severity_report_file, 
                                                         is_group_processing=False, 
                                                         processing_summary=processing_summary)
                    print(f"   📄 Severity report saved to: {severity_report_file}")
                
                return {'success': True, 'matches_processed': 0, 'successful_ignores': 0, 'failed_ignores': 0}
            
            # Enrich issues with target information
            print(f"   🔗 Enriching issues with target information")
            enriched_issues = processor.enrich_issues_with_targets(org_id, all_issues)
            
            # Process issues to get key data
            print(f"   🔍 Processing issue data and fetching details")
            processed_issues = []
            
            for i, issue in enumerate(enriched_issues, 1):
                if i % PROGRESS_BATCH_SIZE == 0 or i == 1:
                    print(f"   📄 Processing issue {i}/{len(enriched_issues)}...")
                
                key_data = processor.extract_issue_key_data(issue)
                if key_data is None:
                    continue  # Skip issues with missing ID
                    
                processed_issue = {
                    'raw_issue': issue,
                    'key_data': key_data
                }
                processed_issues.append(processed_issue)
            
            
            # Match issues with CSV data
            print(f"   🔍 Matching Snyk issues with CSV false positives")
            matches = processor.match_issues_with_csv(
                processed_issues=processed_issues,
                csv_data=csv_data,
                repo_url_field=args.repo_url_field
            )
            
            if not matches:
                print(f"   ℹ️  No matches found between Snyk issues and CSV false positives")
                
                # Generate empty report for audit trail (unless skipping for group processing)
                if not skip_individual_report:
                    print(f"   📊 Generating severity and organization report")
                    severity_report_file = args.severity_report
                    if not severity_report_file:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        severity_report_file = f"snyk_severity_report_{org_name}_{timestamp}.txt"
                    
                    # Create processing summary for empty matches
                    processing_summary = IssueProcessor.create_processing_summary(matches)
                    
                    processor.generate_severity_report(matches, severity_report_file, 
                                                         is_group_processing=False, 
                                                         processing_summary=processing_summary)
                    print(f"   📄 Severity report saved to: {severity_report_file}")
                
                return {'success': True, 'matches_processed': 0, 'successful_ignores': 0, 'failed_ignores': 0}
            
            print(f"   🎯 Found {len(matches)} total matches")
            
            # Process matches and ignore issues
            print(f"   🚫 Processing matches and ignoring issues")
            results = process_matches_and_ignore_policies(
                snyk_api=snyk_api,
                matches=matches,
                dry_run=args.dry_run,
                reason=args.ignore_reason
            )
            
            # Generate severity report (unless skipping for group processing)
            if not skip_individual_report:
                print(f"   📊 Generating severity and organization report")
                severity_report_file = args.severity_report
                if not severity_report_file:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    severity_report_file = f"snyk_severity_report_{org_name}_{timestamp}.txt"
                
                # Create processing summary for single org
                processing_summary = IssueProcessor.create_processing_summary(matches, results)
                
                processor.generate_severity_report(matches, severity_report_file, 
                                                     is_group_processing=False, 
                                                     processing_summary=processing_summary)
                print(f"   📄 Severity report saved to: {severity_report_file}")
            
            # Print final success message
            print(f"   - Matches processed: {len(matches)}")
            print(f"   - Successful ignores: {results['successful_ignores']}")
            print(f"   - Failed ignores: {results['failed_ignores']}")
            
            return {
                'success': True,
                'matches_processed': len(matches),
                'successful_ignores': results['successful_ignores'],
                'failed_ignores': results['failed_ignores'],
                'matches': matches if skip_individual_report else None
            }
        
        # Handle normal workflow
        else:
            print(f"   🔍 Standard matching workflow")
            
            # Initialize issue processor
            processor = IssueProcessor(snyk_api)
            
            # Get all code issues for the organization
            print(f"   🚀 Fetching all code issues for organization {org_id}")
            all_issues = snyk_api.get_all_code_issues(org_id)
            
            if not all_issues:
                print(f"   ℹ️  No code issues found in organization")
                return {'success': True, 'matches_processed': 0, 'successful_ignores': 0, 'failed_ignores': 0}
            
            # Enrich issues with target information
            print(f"   🔗 Enriching issues with target information")
            enriched_issues = processor.enrich_issues_with_targets(org_id, all_issues)
            
            # CSV data should already be loaded and passed in
            if csv_data is None:
                print(f"   ❌ Error: No CSV data provided")
                return {'success': False, 'error': 'No CSV data provided'}
            
            print(f"   📄 Using pre-loaded CSV data ({len(csv_data)} rows)")
            
            # Process issues to get key data
            print(f"   🔍 Processing issue data and fetching details")
            processed_issues = []
            
            for i, issue in enumerate(enriched_issues, 1):
                if i % PROGRESS_BATCH_SIZE == 0 or i == 1:
                    print(f"   📄 Processing issue {i}/{len(enriched_issues)}...")
                
                key_data = processor.extract_issue_key_data(issue)
                if key_data is None:
                    continue  # Skip issues with missing ID
                    
                processed_issue = {
                    'raw_issue': issue,
                    'key_data': key_data
                }
                processed_issues.append(processed_issue)
            
            
            # Match issues with CSV data
            print(f"   🔍 Matching Snyk issues with CSV false positives")
            matches = processor.match_issues_with_csv(
                processed_issues=processed_issues,
                csv_data=csv_data,
                repo_url_field=args.repo_url_field
            )
            
            if not matches:
                print(f"   ℹ️  No matches found between Snyk issues and CSV false positives")
                return {'success': True, 'matches_processed': 0, 'successful_ignores': 0, 'failed_ignores': 0}
            
            print(f"   🎯 Found {len(matches)} total matches")
            
            # Save matches to CSV for review
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            matches_csv_file = f"snyk_matches_{org_name}_{timestamp}.csv"
            
            print(f"   📊 Saving matches to CSV for review")
            save_matches_to_csv(matches, matches_csv_file)
            
            # Process matches and ignore issues (unless review-only mode)
            if args.review_only:
                print(f"   📋 Review-only mode: Matches saved to {matches_csv_file} for review")
                
                # Generate severity report even in review-only mode (unless skipping for group processing)
                if not skip_individual_report:
                    severity_report_file = args.severity_report
                    if not severity_report_file:
                        severity_report_file = f"snyk_severity_report_{org_name}_{timestamp}.txt"
                    
                    # Create processing summary for review-only mode (no ignores)
                    processing_summary = IssueProcessor.create_processing_summary(matches)
                    
                    processor.generate_severity_report(matches, severity_report_file, 
                                                         is_group_processing=False, 
                                                         processing_summary=processing_summary)
                    print(f"   📄 Severity report saved to: {severity_report_file}")
                
                return {
                    'success': True,
                    'matches_processed': len(matches),
                    'successful_ignores': 0,
                    'failed_ignores': 0,
                    'matches_csv': matches_csv_file,
                    'matches': matches if skip_individual_report else None
                }
            else:
                print(f"   🚫 Processing matches and ignoring issues")
                results = process_matches_and_ignore_policies(
                    snyk_api=snyk_api,
                    matches=matches,
                    dry_run=args.dry_run,
                    reason=args.ignore_reason
                )
                
                # Generate severity report
                severity_report_file = args.severity_report
                if not severity_report_file:
                    severity_report_file = f"snyk_severity_report_{org_name}_{timestamp}.txt"
                
                # Create processing summary for single org
                processing_summary = IssueProcessor.create_processing_summary(matches, results)
                
                processor.generate_severity_report(matches, severity_report_file, 
                                                     is_group_processing=False, 
                                                     processing_summary=processing_summary)
                
                return {
                    'success': True,
                    'matches_processed': len(matches),
                    'successful_ignores': results['successful_ignores'],
                    'failed_ignores': results['failed_ignores'],
                    'matches_csv': matches_csv_file,
                    'matches': matches if skip_individual_report else None
                }
    
    except Exception as e:
        print(f"   ❌ Error processing organization {org_name}: {e}")
        return {'success': False, 'error': str(e)}
    
    finally:
        # Restore original org_id
        args.org_id = original_org_id


def main():
    parser = argparse.ArgumentParser(
        description="Transfer ignores from CSV data to Snyk issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Workflow Examples:

1. Complete workflow (match, save CSV, and ignore issues):
  %(prog)s --org-id YOUR_ORG_ID --csv-file issues.csv --dry-run
  %(prog)s --org-id YOUR_ORG_ID --csv-file issues.csv

2. Load matches CSV and process ignores:
  %(prog)s --org-id YOUR_ORG_ID --matches-input snyk_matches_20240101_120000.csv

3. Direct ignore (skip CSV generation, use CSV file directly):
  %(prog)s --org-id YOUR_ORG_ID --csv-file issues.csv --direct-ignore

4. Group processing (process all organizations in a group):
  %(prog)s --group-id YOUR_GROUP_ID --csv-file issues.csv --dry-run
  %(prog)s --group-id YOUR_GROUP_ID --csv-file issues.csv

5. Review-only mode (DEPRECATED - both modes save CSV):
  %(prog)s --org-id YOUR_ORG_ID --csv-file issues.csv --review-only

Note: Both normal and review-only modes save matches to CSV. The only difference
is that review-only mode skips the actual ignoring of issues.
        """
    )

    parser.add_argument('--org-id',
                       help='Snyk organization ID (required if not using --group-id)')
    parser.add_argument('--group-id',
                       help='Snyk group ID to process all organizations in the group')
    parser.add_argument('--csv-file',
                       help='CSV file containing issues to match and ignore (required for normal workflow)')
    parser.add_argument('--repo-url-field', default='repourl',
                       help='Name of the field containing repo URL in CSV (default: repourl)')
    parser.add_argument('--snyk-region', default='SNYK-US-01',
                       help='Snyk API region (default: SNYK-US-01)')
    parser.add_argument('--output-json',
                       help='Save all issues data to JSON file (optional)')
    parser.add_argument('--matches-csv',
                       help='Save matched issues to CSV file for review (optional)')
    parser.add_argument('--matches-input',
                       help='Load previously generated matches CSV file to process ignores')
    parser.add_argument('--dry-run', action='store_true',
                       help='Simulate actions without making changes')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed information')
    parser.add_argument('--ignore-reason', default='False positive identified via CSV analysis',
                       help='Reason for ignoring matched issues')
    parser.add_argument('--review-only', action='store_true',
                       help='Only save matches to CSV for review, do not ignore issues (DEPRECATED: both modes save CSV)')
    parser.add_argument('--direct-ignore', action='store_true',
                       help='Skip CSV generation and proceed directly to ignoring issues (uses --csv-file)')
    parser.add_argument('--severity-report',
                       help='Generate severity and organization report to specified file (optional)')
    parser.add_argument('--df-match', action='store_true',
                       help='Use pandas DataFrame-based matching for improved performance with large datasets')

    args = parser.parse_args()

    # Validate arguments - check for org-id or group-id
    if not args.org_id and not args.group_id:
        print("❌ Error: Either --org-id or --group-id is required")
        parser.print_help()
        sys.exit(1)
    
    if args.org_id and args.group_id:
        print("❌ Error: Cannot use both --org-id and --group-id. Choose one.")
        sys.exit(1)

    # Validate arguments
    if args.matches_input:
        # When loading matches from CSV, only org_id is required (for ignoring)
        # Group processing with matches-input is now supported
        if not args.org_id and not args.group_id:
            print("❌ Error: Either --org-id or --group-id is required when using --matches-input")
            sys.exit(1)
        if args.review_only:
            print("❌ Error: Cannot use --review-only with --matches-input")
            sys.exit(1)
        if args.direct_ignore and not args.csv_file:
            print("❌ Error: --direct-ignore requires --csv-file")
            sys.exit(1)
        if not args.csv_file:
            # csv_file not needed when loading from matches CSV
            pass
    else:
        # Normal workflow validation
        if not args.group_id and not args.org_id:
            print("❌ Error: Either --org-id or --group-id is required for normal workflow")
            parser.print_help()
            sys.exit(1)
        if not args.csv_file:
            print("❌ Error: --csv-file is required for normal workflow")
            sys.exit(1)
        if args.direct_ignore and not args.csv_file:
            print("❌ Error: --direct-ignore requires --csv-file")
            sys.exit(1)

    # Get Snyk token from environment
    snyk_token = os.environ.get('SNYK_TOKEN')
    if not snyk_token:
        print("❌ Error: SNYK_TOKEN environment variable is required")
        sys.exit(1)

    # Initialize Snyk API client
    print(f"🔧 Initializing Snyk API client (region: {args.snyk_region})...")
    snyk_api = SnykAPI(snyk_token, args.snyk_region)

    # Switch to DataFrame-based matching if requested or for large datasets
    if args.df_match:
        print("⚡ Using DataFrame-based matcher (--df-match) for improved performance")
        # Temporarily replace the traditional matcher with the DataFrame version
        IssueProcessor.match_issues_with_csv = IssueProcessor.match_issues_with_csv_df
    elif args.group_id:
        # Auto-enable DataFrame matching for group processing (better performance)
        print("⚡ Auto-enabling DataFrame-based matcher for group processing performance")
        IssueProcessor.match_issues_with_csv = IssueProcessor.match_issues_with_csv_df

    # Handle group processing
    if args.group_id:
        print(f"🏢 Group processing mode - processing all organizations in group {args.group_id}")
        
        # Get all organizations from the group
        orgs = snyk_api.get_all_orgs_from_group(args.group_id)
        
        if not orgs:
            print("❌ Error: No organizations found in group")
            sys.exit(1)
        
        # Load CSV data once for all organizations (if not using matches-input)
        csv_data = None
        if not args.matches_input:
            print(f"📄 Loading CSV data once for all organizations...")
            csv_data = load_csv_data(args.csv_file)
            if not csv_data:
                print("❌ Error: No CSV data loaded. Cannot proceed with group processing.")
                sys.exit(1)
        
        # Process each organization
        total_orgs = len(orgs)
        successful_orgs = 0
        failed_orgs = 0
        total_matches = 0
        total_successful_ignores = 0
        total_failed_ignores = 0
        all_matches = []  # Collect all matches for consolidated report
        
        for i, org in enumerate(orgs, 1):
            org_id = org.get('id')
            org_name = org.get('attributes', {}).get('name', 'Unknown')
            # Skip the org with id fdf3b63a-9a4e-43d8-bae3-85212f002bea to speed up testing REMOVE THIS
            if org_id == "fdf3b63a-9a4e-43d8-bae3-85212f002bea" or org_id == "98107928-6a0b-4ee4-8c3f-c474fc0fb098":
                print(f"   🚫 Skipping organization: {org_name} ({org_id})")
                continue
            org_name = org.get('attributes', {}).get('name', 'Unknown')
            
            print(f"\n🏢 [{i}/{total_orgs}] Processing organization: {org_name} ({org_id})")
            
            # Process the organization using the existing logic, skip individual reports
            result = process_single_organization(snyk_api, args, org_id, org_name, csv_data, direct_ignore=False, skip_individual_report=True)
            
            if result['success']:
                successful_orgs += 1
                total_matches += result.get('matches_processed', 0)
                total_successful_ignores += result.get('successful_ignores', 0)
                total_failed_ignores += result.get('failed_ignores', 0)
                
                # Collect matches for consolidated report
                org_matches = result.get('matches', [])
                if org_matches:
                    all_matches.extend(org_matches)
                
                print(f"   ✅ Completed processing {org_name}")
            else:
                failed_orgs += 1
                print(f"   ❌ Failed processing {org_name}: {result.get('error', 'Unknown error')}")
        
        print(f"\n📊 Group Processing Summary:")
        print(f"   🏢 Total organizations: {total_orgs}")
        print(f"   ✅ Successful: {successful_orgs}")
        print(f"   ❌ Failed: {failed_orgs}")
        if total_matches > 0:
            print(f"   📋 Total matches processed: {total_matches}")
            print(f"   ✅ Total successful ignores: {total_successful_ignores}")
            print(f"   ❌ Total failed ignores: {total_failed_ignores}")
            if args.dry_run:
                print(f"   🏃‍♂️ This was a DRY RUN - no actual changes were made")
        
        # Generate consolidated group severity report (always generate for audit trail)
        print(f"\n📊 Generating consolidated group severity report")
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        group_report_file = args.severity_report
        if not group_report_file:
            group_report_file = f"group_severity_report_{args.group_id}_{timestamp}.txt"
        
        # Create processing summary for the report
        group_stats = {
            'total_orgs': total_orgs,
            'successful_orgs': successful_orgs,
            'failed_orgs': failed_orgs,
            'total_matches': total_matches,
            'successful_ignores': total_successful_ignores,
            'failed_ignores': total_failed_ignores
        }
        processing_summary = IssueProcessor.create_processing_summary(
            all_matches, group_stats, is_group=True, group_stats=group_stats
        )
        
        processor = IssueProcessor(snyk_api)
        processor.generate_severity_report(all_matches, group_report_file, 
                                             is_group_processing=True, 
                                             processing_summary=processing_summary)
        print(f"   📄 Consolidated group report saved to: {group_report_file}")
        
        if not all_matches:
            print(f"   ℹ️  No matches found across all organizations - empty report generated for audit trail")
        
        return  # Exit after group processing

    # Handle two different workflows
    if args.matches_input:
        # Workflow 2: Load matches from CSV and process ignores
        if args.direct_ignore:
            print("🚀 Direct ignore workflow (skipping CSV generation)")
        else:
            print("🔄 Loading matches from CSV workflow")

        matches = load_matches_from_csv(args.matches_input)
        if not matches:
            print("❌ Error: No matches loaded from CSV file")
            sys.exit(1)

        # Set org_id in all loaded matches
        for processed_issue, csv_row in matches:
            processed_issue['key_data']['org_id'] = args.org_id

        print(f"   ✅ Loaded {len(matches)} matches for processing")

        # Skip to ignoring step
        print("\n🚫 Processing loaded matches and ignoring issues")
        results = process_matches_and_ignore_policies(
            snyk_api=snyk_api,
            matches=matches,
            dry_run=args.dry_run,
            reason=args.ignore_reason
        )

        # Display results summary
        display_results_summary(results, dry_run=args.dry_run)

        # Generate severity report (always when ignoring issues)
        print(f"\n📊 Generating severity and organization report")
        severity_report_file = args.severity_report
        if not severity_report_file:
            # Generate default filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            severity_report_file = f"snyk_severity_report_{timestamp}.txt"
        
        # Create processing summary for single org
        processing_summary = IssueProcessor.create_processing_summary(matches, results)
        
        processor = IssueProcessor(snyk_api)
        processor.generate_severity_report(matches, severity_report_file, 
                                             is_group_processing=False, 
                                             processing_summary=processing_summary)
        print(f"   📄 Severity report saved to: {severity_report_file}")

        print("\n🎉 Snyk ignore processing completed successfully!")
        print(f"   - Matches processed: {len(matches)}")
        if args.dry_run:
            print("   - This was a DRY RUN - no actual changes were made")
        else:
            print(f"   - Issues successfully ignored: {results['successful_ignores']}")
        return

    # Workflow 1.5: Direct ignore workflow (skip CSV generation)
    if args.direct_ignore:
        # Load CSV data
        csv_data = load_csv_data(args.csv_file)
        if not csv_data:
            print("❌ Error: No CSV data loaded. Cannot proceed with direct ignore.")
            sys.exit(1)
        
        # Use process_single_organization with direct_ignore=True
        result = process_single_organization(snyk_api, args, args.org_id, "Single Organization", csv_data, direct_ignore=True)
        
        if not result['success']:
            print(f"❌ Error: {result.get('error', 'Unknown error')}")
            sys.exit(1)
        
        print("\n🎉 Direct ignore processing completed successfully!")
        print(f"   - Matches processed: {result.get('matches_processed', 0)}")
        print(f"   - Successful ignores: {result.get('successful_ignores', 0)}")
        print(f"   - Failed ignores: {result.get('failed_ignores', 0)}")
        
        if args.dry_run:
            print("   - This was a DRY RUN - no actual changes were made")
        
        # Note: Severity report is generated within process_single_organization for direct_ignore
        # Always print since report is now always generated for audit trail
        print("   📄 Severity report has been generated and saved")
        
        return

    # Workflow 1: Normal matching workflow
    print("🔍 Standard matching workflow")
    
    # Load CSV data once
    print(f"\n📄 Loading CSV data for comparison")
    csv_data = load_csv_data(args.csv_file)
    
    if not csv_data:
        print("❌ Error: No CSV data loaded. Cannot proceed with matching.")
        sys.exit(1)
    
    # Use process_single_organization for consistency
    result = process_single_organization(snyk_api, args, args.org_id, "Single Organization", csv_data, direct_ignore=False)
    
    if not result['success']:
        print(f"❌ Error: {result.get('error', 'Unknown error')}")
        sys.exit(1)
    
    # Generate severity report for normal workflow (if not already generated in process_single_organization)
    # The severity report is already generated within process_single_organization for normal workflow
    
    print(f"\n📊 Processing completed successfully!")
    print(f"   - Matches processed: {result.get('matches_processed', 0)}")
    print(f"   - Successful ignores: {result.get('successful_ignores', 0)}")
    print(f"   - Failed ignores: {result.get('failed_ignores', 0)}")
    
    if args.dry_run:
        print(f"   - This was a DRY RUN - no actual changes were made")
    
    # Always print since report is now always generated for audit trail
    print("   📄 Severity report has been generated and saved")
    
    return


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n❌ Application error: {str(e)}")
        print("📊 Generating error report for audit trail...")
        
        # Try to generate a minimal error report
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            error_report_file = f"error_report_{timestamp}.txt"
            
            with open(error_report_file, 'w') as f:
                f.write("SNYK IGNORE TRANSFER - ERROR REPORT\n")
                f.write("=" * 40 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Error: {str(e)}\n")
                f.write(f"Status: Application failed\n")
                f.write(f"Matches processed: 0\n")
                f.write(f"Successful ignores: 0\n")
                f.write(f"Failed ignores: 0\n")
            
            print(f"   📄 Error report saved to: {error_report_file}")
        except Exception as report_error:
            print(f"   ❌ Failed to generate error report: {str(report_error)}")
        
        sys.exit(1)
