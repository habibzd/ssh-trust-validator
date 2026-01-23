"""
Reporting Module

Generates human-readable and JSON reports from trust assessments.
"""

import json
from typing import Dict, List, Optional


class Reporter:
    """Generate reports from trust assessments."""
    
    SEVERITY_COLORS = {
        'HIGH': '\033[91m',  # Red
        'WARN': '\033[93m',  # Yellow
        'INFO': '\033[92m',  # Green
    }
    RESET_COLOR = '\033[0m'
    
    def __init__(self, use_colors: bool = True):
        """
        Initialize the reporter.
        
        Args:
            use_colors: Whether to use ANSI color codes in output
        """
        self.use_colors = use_colors
    
    def print_report(self, assessment: Dict, verbose: bool = False):
        """
        Print a human-readable report to stdout.
        
        Args:
            assessment: Assessment dictionary from TrustAssessor
            verbose: Whether to include detailed information
        """
        hostname = assessment['hostname']
        findings = assessment['findings']
        summary = assessment['summary']
        
        print("\n" + "=" * 80)
        print(f"SSH Trust Assessment Report: {hostname}")
        print("=" * 80)
        
        # Summary
        print("\n[SUMMARY]")
        print(f"  Overall Status: {self._colorize(summary['overall_status'].upper(), summary['overall_status'])}")
        print(f"  Total Findings: {summary['total_findings']}")
        print(f"    - HIGH: {summary['high_severity']}")
        print(f"    - WARN: {summary['warn_severity']}")
        print(f"    - INFO: {summary['info_severity']}")
        
        # SSH Configuration
        if verbose:
            print("\n[SSH CONFIGURATION]")
            ssh_config = assessment['ssh_config']
            if ssh_config['parsed']:
                print(f"  Configuration parsed: Yes")
                trust_dirs = ssh_config['trust_directives']
                if trust_dirs:
                    print("  Trust-relevant directives:")
                    for directive, value in trust_dirs.items():
                        print(f"    {directive}: {value}")
                else:
                    print("  No trust-relevant directives found")
            else:
                print("  Configuration parsed: No")
        
        # Host Keys
        if verbose:
            print("\n[HOST KEYS]")
            host_keys = assessment['host_keys']
            print(f"  Keys discovered: {host_keys['count']}")
            for key in host_keys['keys']:
                print(f"    - {key['algorithm']}: {key['file']}")
        
        # SSHFP Records
        if verbose:
            print("\n[SSHFP DNS RECORDS]")
            sshfp = assessment['sshfp_records']
            print(f"  Records found: {sshfp['count']}")
            for record in sshfp['records']:
                print(f"    - Algorithm: {record['algorithm_name']} ({record['algorithm']})")
                print(f"      Fingerprint Type: {record['fingerprint_type_name']}")
                print(f"      Fingerprint: {record['fingerprint']}")
        
        # DNSSEC Validation
        if verbose:
            print("\n[DNSSEC VALIDATION]")
            dnssec = assessment['dnssec_validation']
            status = dnssec['status']
            print(f"  Status: {self._colorize(status.upper(), status)}")
            print(f"  Description: {dnssec['description']}")
            print(f"  AD Flag: {dnssec['ad_flag']}")
            if dnssec.get('resolver_ip'):
                print(f"  Resolver: {dnssec['resolver_ip']}")
        
        # Findings
        print("\n[FINDINGS]")
        if not findings:
            print("  No findings to report.")
        else:
            # Group by severity
            high_findings = [f for f in findings if f['severity'] == 'HIGH']
            warn_findings = [f for f in findings if f['severity'] == 'WARN']
            info_findings = [f for f in findings if f['severity'] == 'INFO']
            
            for finding in high_findings + warn_findings + info_findings:
                self._print_finding(finding)
        
        print("\n" + "=" * 80 + "\n")
    
    def _print_finding(self, finding: Dict):
        """Print a single finding."""
        severity = finding['severity']
        title = finding['title']
        description = finding['description']
        reason = finding.get('reason', '')
        remediation = finding.get('remediation', '')
        
        print(f"\n  [{self._colorize(severity, severity.lower())}] {title}")
        print(f"      Description: {description}")
        if reason:
            print(f"      Reason: {reason}")
        if remediation:
            print(f"      Remediation: {remediation}")
    
    def _colorize(self, text: str, status: str) -> str:
        """Apply color to text based on status."""
        if not self.use_colors:
            return text
        
        color_map = {
            'insecure': 'HIGH',
            'warning': 'WARN',
            'secure': 'INFO',
            'validated': 'INFO',
            'not_validated': 'HIGH',
            'unknown': 'WARN',
            'error': 'WARN',
        }
        
        severity = color_map.get(status, status.upper())
        color = self.SEVERITY_COLORS.get(severity, '')
        
        if color:
            return f"{color}{text}{self.RESET_COLOR}"
        return text
    
    def generate_json(self, assessment: Dict) -> str:
        """
        Generate a JSON report.
        
        Args:
            assessment: Assessment dictionary from TrustAssessor
            
        Returns:
            JSON string
        """
        return json.dumps(assessment, indent=2)
    
    def save_json_report(self, assessment: Dict, output_file: str):
        """
        Save a JSON report to a file.
        
        Args:
            assessment: Assessment dictionary from TrustAssessor
            output_file: Path to output file
        """
        json_str = self.generate_json(assessment)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_str)
