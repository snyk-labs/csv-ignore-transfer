#!/usr/bin/env python3
"""
List Ignore Policies Script

Surface all ignore policies created by the snyk_ignore_transfer tool across a group or organization.
Searches for policies with specific ignore reasons and generates reports.

Usage:
    python3 list_ignore_policies.py --org-id YOUR_ORG_ID
    python3 list_ignore_policies.py --group-id YOUR_GROUP_ID
    python3 list_ignore_policies.py --org-id YOUR_ORG_ID --ignore-reason "Custom reason"
    python3 list_ignore_policies.py --org-id YOUR_ORG_ID --output policies.csv
"""

import json
import argparse
import sys
import os
import csv
import requests
from datetime import datetime
from typing import Dict, List, Optional

# Import from the main script
try:
    from snyk_ignore_transfer import SnykAPI, Config
except ImportError:
    print("❌ Error: Could not import from snyk_ignore_transfer.py")
    print("   Make sure snyk_ignore_transfer.py is in the same directory")
    sys.exit(1)


class IgnorePolicyFinder:
    """Find and report on ignore policies in Snyk."""
    
    def __init__(self, snyk_api: SnykAPI):
        self.snyk_api = snyk_api
    
    def get_ignore_policies(self, org_id: str, version: str = "2024-10-15") -> List[Dict]:
        """
        Get all ignore policies for a Snyk organization.
        
        Args:
            org_id: Organization ID
            version: API version
            
        Returns:
            List of ignore policies
        """
        url = f"{self.snyk_api.base_url}/rest/orgs/{org_id}/policies"
        params = {
            'version': version,
            'limit': 100
        }
        
        all_policies = []
        next_url = url
        next_params = params
        page = 1
        
        while next_url:
            print(f"   📄 Fetching policies page {page}...")
            try:
                response = self.snyk_api.session.get(next_url, params=next_params)
                response.raise_for_status()
                data = response.json()
                
                policies = data.get('data', [])
                all_policies.extend(policies)
                
                # Handle pagination
                links = data.get('links', {})
                next_url = links.get('next')
                next_params = None
                
                if next_url:
                    if next_url.startswith('http'):
                        pass  # use as-is
                    elif next_url.startswith('/'):
                        next_url = self.snyk_api.base_url + next_url
                    else:
                        next_url = self.snyk_api.base_url + '/' + next_url.lstrip('/')
                else:
                    next_url = None
                    
                page += 1
            except requests.exceptions.RequestException as e:
                print(f"   ⚠️  Warning: Error fetching page {page}: {e}")
                break
        
        print(f"   ✅ Found {len(all_policies)} total policies")
        return all_policies
    
    def get_policy_events(self, org_id: str, policy_id: str, version: str = "2024-10-15") -> List[Dict]:
        """
        Get all events for a specific policy.
        
        Args:
            org_id: Organization ID
            policy_id: Policy ID
            version: API version
            
        Returns:
            List of policy events
        """
        url = f"{self.snyk_api.base_url}/rest/orgs/{org_id}/policies/{policy_id}/events"
        params = {
            'version': version,
            'limit': 100
        }
        
        all_events = []
        next_url = url
        next_params = params
        page = 1
        
        while next_url:
            try:
                response = self.snyk_api.session.get(next_url, params=next_params)
                response.raise_for_status()
                data = response.json()
                
                events = data.get('data', [])
                all_events.extend(events)
                
                # Handle pagination
                links = data.get('links', {})
                next_url = links.get('next')
                next_params = None
                
                if next_url:
                    if next_url.startswith('http'):
                        pass  # use as-is
                    elif next_url.startswith('/'):
                        next_url = self.snyk_api.base_url + next_url
                    else:
                        next_url = self.snyk_api.base_url + '/' + next_url.lstrip('/')
                else:
                    next_url = None
                    
                page += 1
            except requests.exceptions.RequestException as e:
                # Don't print warnings for every 403/404 - just return empty list
                if hasattr(e.response, 'status_code') and e.response.status_code not in [403, 404]:
                    print(f"      ⚠️  Warning: Error fetching events for policy {policy_id}: {e}")
                break
        
        return all_events
    
    def filter_by_ignore_reason(self, policies: List[Dict], ignore_reason: str) -> List[Dict]:
        """
        Filter policies by ignore reason and action type.
        
        Args:
            policies: List of policies
            ignore_reason: The ignore reason to search for (partial match)
            
        Returns:
            List of policies that match the ignore reason
        """
        matching_policies = []
        
        for policy in policies:
            attributes = policy.get('attributes', {})
            
            # Check if it's an ignore policy
            action_type = attributes.get('action_type')
            if action_type != 'ignore':
                continue
            
            # Check the reason in the action data
            action = attributes.get('action', {})
            action_data = action.get('data', {})
            reason = action_data.get('reason', '')
            
            if ignore_reason.lower() in reason.lower():
                matching_policies.append(policy)
        
        return matching_policies
    
    def enrich_policies_with_events(self, org_id: str, policies: List[Dict]) -> List[Dict]:
        """
        Enrich policies with their event history.
        
        Args:
            org_id: Organization ID
            policies: List of policies
            
        Returns:
            List of policies enriched with events
        """
        enriched_policies = []
        
        for i, policy in enumerate(policies, 1):
            policy_id = policy.get('id')
            policy_name = policy.get('attributes', {}).get('name', 'Unnamed')
            
            if i <= 3 or i % 10 == 0:
                print(f"      [{i}/{len(policies)}] Fetching events for: {policy_name[:60]}...")
            
            events = self.get_policy_events(org_id, policy_id)
            
            enriched_policy = policy.copy()
            enriched_policy['events'] = events
            enriched_policies.append(enriched_policy)
        
        return enriched_policies


def save_to_csv(policies: List[Dict], filename: str, ignore_reason: str):
    """
    Save ignore policies and their events to a CSV file.
    
    Args:
        policies: List of policies (enriched with events)
        filename: Output CSV filename
        ignore_reason: The ignore reason being searched for
    """
    if not policies:
        print(f"   ℹ️  No policies to save")
        return
    
    fieldnames = [
        'policy_id',
        'policy_name',
        'action_type',
        'ignore_type',
        'reason',
        'key_asset',
        'created_at',
        'updated_at',
        'created_by_name',
        'created_by_email'
    ]
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for policy in policies:
            policy_id = policy.get('id', '')
            attributes = policy.get('attributes', {})
            action = attributes.get('action', {})
            action_data = action.get('data', {})
            created_by = attributes.get('created_by', {})
            
            # Extract key_asset from conditions
            conditions_group = attributes.get('conditions_group', {})
            conditions = conditions_group.get('conditions', [])
            key_asset = ''
            for condition in conditions:
                if condition.get('field') == 'snyk/asset/finding/v1':
                    key_asset = condition.get('value', '')
                    break
            
            writer.writerow({
                'policy_id': policy_id,
                'policy_name': attributes.get('name', ''),
                'action_type': attributes.get('action_type', ''),
                'ignore_type': action_data.get('ignore_type', ''),
                'reason': action_data.get('reason', ''),
                'key_asset': key_asset,
                'created_at': attributes.get('created_at', ''),
                'updated_at': attributes.get('updated_at', ''),
                'created_by_name': created_by.get('name', ''),
                'created_by_email': created_by.get('email', '')
            })
    
    print(f"   📄 Saved {len(policies)} policies to {filename}")


def print_summary(policies: List[Dict], ignore_reason: str, org_name: str = None):
    """
    Print a summary of ignore policies.
    
    Args:
        policies: List of policies
        ignore_reason: The ignore reason being searched for
        org_name: Optional organization name
    """
    print(f"\n{'='*80}")
    print(f"📊 IGNORE POLICIES SUMMARY")
    print(f"{'='*80}")
    
    if org_name:
        print(f"Organization: {org_name}")
    print(f"Ignore Reason: \"{ignore_reason}\"")
    print(f"Total Ignore Policies: {len(policies)}")
    
    if not policies:
        print("\nℹ️  No ignore policies found with this reason")
        return
    
    # Count by ignore type
    ignore_type_counts = {}
    
    # Count by creation date
    dates = []
    
    for policy in policies:
        attributes = policy.get('attributes', {})
        action = attributes.get('action', {})
        action_data = action.get('data', {})
        
        # Count ignore types
        ignore_type = action_data.get('ignore_type', 'unknown')
        ignore_type_counts[ignore_type] = ignore_type_counts.get(ignore_type, 0) + 1
        
        # Track dates
        created = attributes.get('created_at', '')
        if created:
            dates.append(created)
    
    # Print ignore type breakdown
    print(f"\n📊 By Ignore Type:")
    for ignore_type, count in sorted(ignore_type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   {ignore_type}: {count}")
    
    # Print date range
    if dates:
        dates_sorted = sorted(dates)
        print(f"\n📅 Date Range:")
        print(f"   First created: {dates_sorted[0][:10]}")
        print(f"   Last created: {dates_sorted[-1][:10]}")
    
    print(f"\n{'='*80}")


def process_organization(finder: IgnorePolicyFinder, org_id: str, org_name: str, 
                        ignore_reason: str, output_file: str = None) -> Dict:
    """
    Process a single organization to find ignore policies.
    
    Args:
        finder: IgnorePolicyFinder instance
        org_id: Organization ID
        org_name: Organization name
        ignore_reason: Ignore reason to search for
        output_file: Optional output CSV file
        
    Returns:
        Dictionary with results
    """
    print(f"\n🔍 Processing organization: {org_name} ({org_id})")
    
    # Get all policies
    print("   📥 Fetching policies...")
    policies = finder.get_ignore_policies(org_id)
    
    if not policies:
        print("   ℹ️  No policies found")
        return {'org_id': org_id, 'org_name': org_name, 'count': 0, 'policies': []}
    
    # Filter by ignore reason
    print(f"   🔍 Filtering by ignore reason: \"{ignore_reason}\"...")
    matching_policies = finder.filter_by_ignore_reason(policies, ignore_reason)
    print(f"   ✅ Found {len(matching_policies)} policies with matching ignore reason")
    
    if not matching_policies:
        return {'org_id': org_id, 'org_name': org_name, 'count': 0, 'policies': []}
    
    # Save to CSV if requested
    if output_file:
        save_to_csv(matching_policies, output_file, ignore_reason)
    
    # Print summary
    print_summary(matching_policies, ignore_reason, org_name)
    
    return {
        'org_id': org_id,
        'org_name': org_name,
        'count': len(matching_policies),
        'policies': matching_policies
    }


def main():
    parser = argparse.ArgumentParser(
        description="List ignore policies created by the snyk_ignore_transfer tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List ignore policies for an organization
  python3 list_ignore_policies.py --org-id abc123-def456

  # List ignore policies for all organizations in a group
  python3 list_ignore_policies.py --group-id xyz789

  # Search for custom ignore reason
  python3 list_ignore_policies.py --org-id abc123 --ignore-reason "Custom reason"

  # Save results to CSV
  python3 list_ignore_policies.py --org-id abc123 --output policies.csv
        """
    )
    
    parser.add_argument('--org-id',
                       help='Snyk organization ID (required if not using --group-id)')
    parser.add_argument('--group-id',
                       help='Snyk group ID to process all organizations')
    parser.add_argument('--ignore-reason',
                       default='False positive identified via CSV analysis',
                       help='Ignore reason to search for (default: "False positive identified via CSV analysis")')
    parser.add_argument('--snyk-region',
                       default='SNYK-US-01',
                       help='Snyk API region (default: SNYK-US-01)')
    parser.add_argument('--output',
                       help='Output CSV file (optional)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.org_id and not args.group_id:
        print("❌ Error: Either --org-id or --group-id is required")
        parser.print_help()
        sys.exit(1)
    
    if args.org_id and args.group_id:
        print("❌ Error: Cannot use both --org-id and --group-id. Choose one.")
        sys.exit(1)
    
    # Get Snyk token
    snyk_token = os.environ.get('SNYK_TOKEN')
    if not snyk_token:
        print("❌ Error: SNYK_TOKEN environment variable is required")
        sys.exit(1)
    
    print("🔧 Initializing Snyk API client...")
    snyk_api = SnykAPI(snyk_token, args.snyk_region)
    finder = IgnorePolicyFinder(snyk_api)
    
    # Process group or single organization
    if args.group_id:
        print(f"\n📦 Processing group: {args.group_id}")
        
        # Get all organizations in the group
        orgs = snyk_api.get_all_orgs_from_group(args.group_id)
        print(f"   ✅ Found {len(orgs)} organizations in group")
        
        all_results = []
        total_policies = 0
        
        for i, org in enumerate(orgs, 1):
            org_id = org.get('id')
            org_name = org.get('attributes', {}).get('name', 'Unknown')
            
            print(f"\n[{i}/{len(orgs)}] Processing: {org_name}")
            
            # Generate org-specific output file if base output is provided
            org_output_file = None
            if args.output:
                base_name, ext = os.path.splitext(args.output)
                org_output_file = f"{base_name}_{org_name.replace(' ', '_')}{ext}"
            
            result = process_organization(
                finder, org_id, org_name,
                args.ignore_reason, org_output_file
            )
            
            all_results.append(result)
            total_policies += result['count']
        
        # Print group summary
        print(f"\n{'='*80}")
        print(f"📊 GROUP SUMMARY")
        print(f"{'='*80}")
        print(f"Total Organizations: {len(orgs)}")
        print(f"Total Ignore Policies: {total_policies}")
        print(f"\nBreakdown by Organization:")
        for result in all_results:
            if result['count'] > 0:
                print(f"   {result['org_name']}: {result['count']}")
        print(f"{'='*80}")
        
    else:
        # Single organization
        org_id = args.org_id
        org_name = "Single Organization"
        
        result = process_organization(
            finder, org_id, org_name,
            args.ignore_reason, args.output
        )
        
        if result['count'] == 0:
            print(f"\n✅ No ignore policies found with reason: \"{args.ignore_reason}\"")
        else:
            print(f"\n✅ Found {result['count']} ignore policies")
    
    print("\n🎉 Processing complete!")


if __name__ == "__main__":
    main()

