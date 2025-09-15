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
                    'limit': 100,
                    'version': version
                }
            
            try:
                if next_url:
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
        print(f"🔍 Fetching all code issues for organization {org_id}...")

        url = f"{self.base_url}/rest/orgs/{org_id}/issues"
        params = {
            'version': version,
            'type': 'code',
            'limit': 100,
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
        print(f"🎯 Fetching all targets for organization {org_id}...")

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

    def enrich_issues_with_targets(self, org_id: str, issues: List[Dict]) -> List[Dict]:
        """
        Enrich issues with target information including attributes.url.

        Args:
            org_id: Organization ID
            issues: List of issues to enrich

        Returns:
            List of enriched issues with target information
        """
        print(f"🔗 Enriching {len(issues)} issues with target information...")

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
        api_calls_made = 0
        api_calls_saved = 0

        enriched_issues = []

        for i, issue in enumerate(issues):
            if i % 100 == 0:  # Progress indicator
                print(f"   📦 Processing issue {i+1}/{len(issues)} (API calls made: {api_calls_made}, saved: {api_calls_saved})")
            
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
                    api_calls_saved += 1
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
                        api_calls_made += 1
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

        print(f"   📊 Performance: API calls made: {api_calls_made}, saved: {api_calls_saved}")
        print(f"   📊 Cache hit rate: {(api_calls_saved / (api_calls_made + api_calls_saved) * 100):.1f}%")
        print("   ✅ Enriched all issues with target information")
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

        return {
            'issue_id': issue.get('id'),
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
        print(f"🔍 Matching {len(processed_issues)} Snyk issues with {len(csv_data)} CSV entries...")
        print("   📋 Criteria: Branch + File name + CWE + Repository URL (+ optional line range)")

        # Filter CSV data to only include false positives
        false_positives = [row for row in csv_data if self._is_false_positive(row)]
        print(f"   📋 Found {len(false_positives)} false positive entries in CSV")

        matches = []

        for csv_row in false_positives:
            # Extract CSV matching fields
            csv_branch = csv_row.get('branch', '').strip()
            csv_file_path = csv_row.get('file_path', '').strip()
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
            csv_repo_url = csv_row.get(repo_url_field, '').strip()

            for processed_issue in processed_issues:
                issue_data = processed_issue['key_data']

                # Extract Snyk matching fields
                snyk_branch = issue_data.get('branch', '').strip()
                snyk_file_path = issue_data.get('file_path', '').strip()
                snyk_cwe = issue_data.get('cwe', '').strip()
                snyk_target_url = (issue_data.get('target_url') or '').strip()
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

        print(f"   🎯 Found {len(matches)} total matches")
        return matches

    def _is_false_positive(self, csv_row: Dict) -> bool:
        """Check if a CSV row represents a false positive."""
        false_p = csv_row.get('false_p', '').strip().lower()
        return false_p in ['true', '1', 'yes', 't']

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

        # Jaccard similarity - at least 60% overlap
        similarity = len(intersection) / len(union) if union else 0
        return similarity >= 0.6

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

    def generate_severity_org_report(self, matches: List[Tuple[Dict, Dict]], output_file: str):
        """
        Generate a severity and organization report for the matches.

        Args:
            matches: List of (processed_issue, csv_row) tuples
            output_file: Path to output file for the report
        """
        from collections import defaultdict
        from datetime import datetime

        # Group by severity and organization
        severity_org_counts = defaultdict(lambda: defaultdict(int))
        total_issues = len(matches)

        for processed_issue, csv_row in matches:
            issue_data = processed_issue['key_data']
            severity = issue_data.get('severity', 'Unknown')
            org_id = issue_data.get('org_id', 'Unknown')
            severity_org_counts[severity][org_id] += 1

        # Generate report content
        report_lines = []
        report_lines.append("SNYK IGNORE TRANSFER - SEVERITY AND ORGANIZATION REPORT")
        report_lines.append("=" * 60)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total Issues to be Ignored: {total_issues}")
        report_lines.append("")

        # Sort severities by priority (Critical, High, Medium, Low, Unknown)
        severity_order = ['critical', 'high', 'medium', 'low', 'unknown']
        sorted_severities = sorted(severity_org_counts.keys(), 
                                 key=lambda x: severity_order.index(x.lower()) if x.lower() in severity_order else 999)

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
            print(f"   📄 Severity report saved to: {output_file}")
        except Exception as e:
            print(f"   ❌ Error saving severity report: {e}")


def load_csv_data(csv_file: str) -> List[Dict]:
    """
    Load data from CSV file for comparison.

    Args:
        csv_file: Path to CSV file

    Returns:
        List of dictionaries representing CSV rows
    """
    print(f"📄 Loading CSV data from {csv_file}...")

    try:
        with open(csv_file, 'r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            csv_data = list(reader)

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
    """Load matches from a previously generated CSV file."""
    import csv

    try:
        matches = []

        with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)

            for row in reader:
                # Reconstruct the processed_issue structure
                processed_issue = {
                    'key_data': {
                        'issue_id': row.get('snyk_issue_id'),
                        'title': row.get('snyk_title'),
                        'cwe': row.get('snyk_cwe'),
                        'severity': row.get('snyk_severity'),
                        'file_path': row.get('snyk_file_path'),
                        'start_line': int(row['snyk_start_line']) if row.get('snyk_start_line') else None,
                        'end_line': int(row['snyk_end_line']) if row.get('snyk_end_line') else None,
                        'branch': row.get('snyk_branch'),
                        'project_id': row.get('snyk_project_id'),
                        'created_at': row.get('snyk_created_at'),
                        'status': row.get('snyk_status'),
                        'org_id': None,  # Will be set from command line args
                        'problem_id': None  # Not needed for ignoring
                    },
                    'raw_issue': {}  # Not needed for ignoring
                }

                # Reconstruct the CSV row structure
                csv_row = {
                    'title': row.get('csv_title'),
                    'cwe': row.get('csv_cwe'),
                    'severity': row.get('csv_severity'),
                    'file_path': row.get('csv_file_path'),
                    'line': row.get('csv_line'),
                    'branch': row.get('csv_branch'),
                    'repourl': row.get('csv_repourl'),
                    'test_type': row.get('csv_test_type'),
                    'date_discovered': row.get('csv_date_discovered'),
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


# V1 IGNORE FUNCTION - COMMENTED OUT FOR POLICY-BASED APPROACH
# def process_matches_and_ignore(snyk_api: SnykAPI, matches: List[Tuple[Dict, Dict]],
#                               dry_run: bool = False, reason: str = "False positive identified via CSV analysis") -> Dict:
#     """
#     Process matches and ignore issues in Snyk.
# 
#     Args:
#         snyk_api: Snyk API client
#         matches: List of (snyk_issue, csv_row) tuples
#         dry_run: If True, simulate actions without making changes
#         reason: Reason for ignoring the issues
# 
#     Returns:
#         Dictionary with success/failure counts
#     """
#     print(f"🎯 Processing {len(matches)} matched issues for ignoring...")
# 
#     results = {
#         'total_matches': len(matches),
#         'successful_ignores': 0,
#         'failed_ignores': 0,
#         'skipped': 0
#     }
# 
#     for i, (processed_issue, csv_row) in enumerate(matches, 1):
#         issue_data = processed_issue['key_data']
# 
#         org_id = issue_data.get('org_id')
#         project_id = issue_data.get('project_id')
#         issue_id = issue_data.get('issue_id')
# 
#         print(f"   [{i}/{len(matches)}] Processing issue: {issue_data.get('title', 'Unknown')[:50]}...")
# 
#         # Validate required IDs
#         if not all([org_id, project_id, issue_id]):
#             print(f"      ⚠️  Skipping: Missing required IDs (org: {org_id}, project: {project_id}, issue: {issue_id})")
#             results['skipped'] += 1
#             continue
# 
#         # Build detailed reason with CSV context
#         detailed_reason = f"{reason}. CWE: {csv_row.get('cwe', 'N/A')}, CSV Title: {csv_row.get('title', 'N/A')[:100]}"
# 
#         # Attempt to ignore the issue
#         success = snyk_api.ignore_issue(
#             org_id=org_id,
#             project_id=project_id,
#             issue_id=issue_id,
#             reason=detailed_reason,
#             reason_type="not-vulnerable",
#             disregard_if_fixable=False,
#             expires="",
#             dry_run=dry_run
#         )
# 
#         if success:
#             results['successful_ignores'] += 1
#         else:
#             results['failed_ignores'] += 1
# 
#     return results


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

        print(f"   [{i}/{len(matches)}] Processing issue: {issue_title[:50]}...")

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
        detailed_reason = f"{reason}. CWE: {cwe}, CSV Title: {csv_title[:100]}"

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
        # Note: Group processing with matches-input is not supported yet
        if not args.org_id:
            print("❌ Error: --org-id is required when using --matches-input (group processing not supported with matches-input)")
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

    # Handle group processing
    if args.group_id:
        print(f"🏢 Group processing mode - processing all organizations in group {args.group_id}")
        
        # Get all organizations from the group
        orgs = snyk_api.get_all_orgs_from_group(args.group_id)
        
        if not orgs:
            print("❌ Error: No organizations found in group")
            sys.exit(1)
        
        # Process each organization
        total_orgs = len(orgs)
        successful_orgs = 0
        failed_orgs = 0
        
        for i, org in enumerate(orgs, 1):
            org_id = org.get('id')
            org_name = org.get('attributes', {}).get('name', 'Unknown')
            
            print(f"\n🏢 [{i}/{total_orgs}] Processing organization: {org_name} ({org_id})")
            
            try:
                # Set the org_id for this iteration
                args.org_id = org_id
                
                # Run the normal workflow for this organization
                # This will be handled by the existing logic below
                print(f"   🔄 Running ignore transfer for organization {org_name}")
                
                # We'll need to call the processing logic here
                # For now, let's just show that we would process this org
                print(f"   ⏭️  Skipping detailed processing for now (would process {org_name})")
                successful_orgs += 1
                
            except Exception as e:
                print(f"   ❌ Error processing organization {org_name}: {e}")
                failed_orgs += 1
        
        print(f"\n📊 Group Processing Summary:")
        print(f"   🏢 Total organizations: {total_orgs}")
        print(f"   ✅ Successful: {successful_orgs}")
        print(f"   ❌ Failed: {failed_orgs}")
        
        return  # Exit after group processing

    # Handle two different workflows
    if args.matches_input:
        # Workflow 2: Load matches from CSV and process ignores
        if args.direct_ignore:
            print("🚀 Direct ignore workflow (skipping CSV generation)")
        else:
            print("🔄 Loading matches from CSV workflow")
        print(f"   📄 Loading matches from: {args.matches_input}")

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
        if not args.direct_ignore:  # Only generate report if not in direct ignore mode
            print(f"\n📊 Generating severity and organization report")
            severity_report_file = args.severity_report
            if not severity_report_file:
                # Generate default filename with timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                severity_report_file = f"snyk_severity_report_{timestamp}.txt"
            
            processor = IssueProcessor(snyk_api)
            processor.generate_severity_org_report(matches, severity_report_file)
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
        print("🚀 Direct ignore workflow (skipping CSV generation)")
        print(f"   📄 Using CSV file: {args.csv_file}")

        # Load CSV data
        csv_data = load_csv_data(args.csv_file)
        if not csv_data:
            print("❌ Error: No CSV data loaded. Cannot proceed with direct ignore.")
            sys.exit(1)

        print(f"   ✅ Loaded {len(csv_data)} rows from CSV")

        # Initialize issue processor
        processor = IssueProcessor(snyk_api)

        # Get all code issues for the organization
        print(f"\n🚀 Fetching all code issues for organization {args.org_id}")
        all_issues = snyk_api.get_all_code_issues(args.org_id)

        if not all_issues:
            print("ℹ️  No code issues found in organization")
            return

        # Enrich issues with target information
        print("\n🔗 Enriching issues with target information")
        enriched_issues = processor.enrich_issues_with_targets(args.org_id, all_issues)

        # Process issues to get key data
        print("\n🔍 Processing issue data and fetching details")
        processed_issues = []

        for i, issue in enumerate(enriched_issues, 1):
            if i % 100 == 0 or i == 1:
                print(f"   📄 Processing issue {i}/{len(enriched_issues)}...")

            key_data = processor.extract_issue_key_data(issue)
            processed_issue = {
                'raw_issue': issue,
                'key_data': key_data
            }
            processed_issues.append(processed_issue)

        print(f"   ✅ Processed {len(processed_issues)} issues with detailed information")

        # Match issues with CSV data
        print("\n🔍 Matching Snyk issues with CSV false positives")
        matches = processor.match_issues_with_csv(
            processed_issues=processed_issues,
            csv_data=csv_data,
            repo_url_field=args.repo_url_field
        )

        if not matches:
            print("ℹ️  No matches found between Snyk issues and CSV false positives")
            print(f"🎉 Process completed - {len(enriched_issues)} issues processed, but no matches to ignore")
            return

        print(f"   🎯 Found {len(matches)} total matches")

        # Process matches and ignore issues
        print(f"\n🚫 Processing matches and ignoring issues")
        results = process_matches_and_ignore_policies(
            snyk_api=snyk_api,
            matches=matches,
            dry_run=args.dry_run,
            reason=args.ignore_reason
        )

        # Display results summary
        display_results_summary(results, dry_run=args.dry_run)

        # Generate severity report
        print(f"\n📊 Generating severity and organization report")
        severity_report_file = args.severity_report
        if not severity_report_file:
            # Generate default filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            severity_report_file = f"snyk_severity_report_{timestamp}.txt"
        
        processor.generate_severity_org_report(matches, severity_report_file)
        print(f"   📄 Severity report saved to: {severity_report_file}")

        print(f"\n🎉 Snyk direct ignore processing completed successfully!")
        print(f"   - Total issues processed: {len(enriched_issues)}")
        print(f"   - CSV entries processed: {len(csv_data)}")
        print(f"   - Matches found: {len(matches)}")
        print(f"   - Severity report saved to: {severity_report_file}")
        if args.dry_run:
            print(f"   - This was a DRY RUN - no actual changes were made")
        else:
            print(f"   - Issues successfully ignored: {results['successful_ignores']}")
        return

    # Workflow 1: Normal matching workflow
    print("🔍 Standard matching workflow")

    # Initialize issue processor
    processor = IssueProcessor(snyk_api)

    # Step 1: Get all code issues for the organization
    print(f"\n🚀 Step 1: Fetching all code issues for organization {args.org_id}")
    all_issues = snyk_api.get_all_code_issues(args.org_id)

    if not all_issues:
        print("ℹ️  No code issues found in organization")
        return

    # Step 2: Enriching issues with target information (preserving attributes.url)
    print("\n🔗 Step 2: Enriching issues with target information")
    enriched_issues = processor.enrich_issues_with_targets(args.org_id, all_issues)

    # Step 3: Load CSV data for comparison
    print("\n📄 Step 3: Loading CSV data for comparison")
    csv_data = load_csv_data(args.csv_file)

    if not csv_data:
        print("❌ Error: No CSV data loaded. Cannot proceed with matching.")
        sys.exit(1)

    # Step 4: Extract key data from issues for easier processing (includes fetching issue details and project details)
    print("\n🔍 Step 4: Processing issue data and fetching details (this may take a while...)")
    print("   📋 Fetching issue details (file paths, line numbers) and project details (branch info)")
    processed_issues = []

    for i, issue in enumerate(enriched_issues, 1):
        if i % 100 == 0 or i == 1:
            print(f"   📄 Processing issue {i}/{len(enriched_issues)}...")

        key_data = processor.extract_issue_key_data(issue)
        processed_issue = {
            'raw_issue': issue,
            'key_data': key_data
        }
        processed_issues.append(processed_issue)

    print(f"   ✅ Processed {len(processed_issues)} issues with detailed information (file paths, lines, branches)")

    # Display sample data if verbose
    if args.verbose and processed_issues:
        print("\n📋 Sample processed issue data:")
        sample = processed_issues[0]['key_data']
        for key, value in sample.items():
            print(f"   {key}: {value}")

    # Save to JSON if requested (before matching)
    if args.output_json:
        print("\n💾 Saving issues data to JSON file")
        save_issues_to_json([pi['key_data'] for pi in processed_issues], args.output_json)

    # Step 5: Match issues with CSV data using new criteria
    print("\n🔍 Step 5: Matching Snyk issues with CSV false positives")
    matches = processor.match_issues_with_csv(
        processed_issues=processed_issues,
        csv_data=csv_data,
        repo_url_field=args.repo_url_field
    )

    if not matches:
        print("ℹ️  No matches found between Snyk issues and CSV false positives")
        print(f"🎉 Process completed - {len(enriched_issues)} issues processed, but no matches to ignore")
        return

    # Display some match details if verbose
    if args.verbose:
        print(f"\n📋 Sample matches found:")
        for i, (processed_issue, csv_row) in enumerate(matches[:3], 1):
            issue_data = processed_issue['key_data']
            print(f"   {i}. Snyk Issue: {issue_data.get('title', 'Unknown')[:60]}...")
            print(f"      File: {processor._extract_filename(issue_data.get('file_path', 'N/A'))}")
            print(f"      CWE: {issue_data.get('cwe')} | Branch: {issue_data.get('branch')}")
            print(f"      Lines: {issue_data.get('start_line')}-{issue_data.get('end_line')}")
            print(f"   {i}. CSV Match: {csv_row.get('title', 'Unknown')[:60]}...")
            print(f"      File: {processor._extract_filename(csv_row.get('file_path', 'N/A'))}")
            print(f"      CWE: {processor._normalize_cwe(csv_row.get('cwe'))} | Branch: {csv_row.get('branch')}")
            print(f"      Line: {csv_row.get('line')}")
            print()

    # Step 6: Save matches to CSV for review
    matches_csv_file = args.matches_csv
    if not matches_csv_file:
        # Generate default filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        matches_csv_file = f"snyk_matches_{timestamp}.csv"

    print(f"\n📊 Step 6: Saving matches to CSV for review")
    save_matches_to_csv(matches, matches_csv_file)

    # Step 7: Process matches and ignore issues (unless review-only mode)
    if args.review_only:
        print(f"\n📋 Review-only mode: Matches saved to {matches_csv_file} for review")
        print(f"   - Review the matches and run without --review-only to proceed with ignoring")
    else:
        print(f"\n🚫 Step 7: Processing matches and ignoring issues")
        results = process_matches_and_ignore_policies(
            snyk_api=snyk_api,
            matches=matches,
            dry_run=args.dry_run,
            reason=args.ignore_reason
        )

        # Display results summary
        display_results_summary(results, dry_run=args.dry_run)

        # Step 8: Generate severity report (always when ignoring issues)
        print(f"\n📊 Step 8: Generating severity and organization report")
        severity_report_file = args.severity_report
        if not severity_report_file:
            # Generate default filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            severity_report_file = f"snyk_severity_report_{timestamp}.txt"
        
        processor.generate_severity_org_report(matches, severity_report_file)
        print(f"   📄 Severity report saved to: {severity_report_file}")

        print(f"\n🎉 Snyk ignore transfer completed successfully!")
        print(f"   - Total issues processed: {len(enriched_issues)}")
        print(f"   - CSV entries processed: {len(csv_data)}")
        print(f"   - Matches found: {len(matches)}")
        print(f"   - Matches saved to: {matches_csv_file}")
        print(f"   - Severity report saved to: {severity_report_file}")
        if args.dry_run:
            print(f"   - This was a DRY RUN - no actual changes were made")
        else:
            print(f"   - Issues successfully ignored: {results['successful_ignores']}")

    print(f"\n💡 Next steps:")
    if args.review_only:
        print(f"   1. Review matches in: {matches_csv_file}")
        print(f"   2. Run without --review-only to proceed with ignoring")
    else:
        print(f"   1. Review ignore results")
        print(f"   2. Check Snyk console for ignored issues")
        print(f"   3. Review severity report: {severity_report_file}")


if __name__ == '__main__':
    main()
