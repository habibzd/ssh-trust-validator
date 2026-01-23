#!/usr/bin/env python3
"""
SSH Trust Validator - Main CLI Entry Point

A tool for detecting SSH trust misconfigurations by analyzing:
- SSH server configuration
- SSH host keys
- DNS SSHFP records
- DNSSEC validation status
"""

import argparse
import sys
from pathlib import Path

from trust_assessor import TrustAssessor
from reporter import Reporter


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='SSH Trust Validator - Detect SSH trust misconfigurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Assess localhost (default paths)
  python main.py localhost

  # Assess with custom resolver
  python main.py example.com --resolver 192.168.1.100

  # Custom SSH config path
  python main.py example.com --ssh-config /custom/path/sshd_config

  # Generate JSON output
  python main.py example.com --json output.json

  # Verbose output
  python main.py example.com --verbose
        """
    )
    
    parser.add_argument(
        'hostname',
        help='Hostname to assess'
    )
    
    parser.add_argument(
        '--ssh-config',
        default='/etc/ssh/sshd_config',
        help='Path to sshd_config file (default: /etc/ssh/sshd_config)'
    )
    
    parser.add_argument(
        '--host-key-dir',
        default='/etc/ssh',
        help='Directory containing SSH host keys (default: /etc/ssh)'
    )
    
    parser.add_argument(
        '--resolver',
        default=None,
        help='Custom DNS resolver IP address (validating resolver)'
    )
    
    parser.add_argument(
        '--json',
        default=None,
        metavar='FILE',
        help='Output JSON report to file'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed information'
    )
    
    args = parser.parse_args()
    
    # Initialize components
    try:
        assessor = TrustAssessor(
            ssh_config_path=args.ssh_config,
            host_key_dir=args.host_key_dir,
            resolver_ip=args.resolver
        )
        
        reporter = Reporter(use_colors=not args.no_color)
        
    except Exception as e:
        print(f"Error initializing validator: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Perform assessment
    try:
        print(f"Assessing SSH trust configuration for {args.hostname}...")
        assessment = assessor.assess_host(args.hostname)
        
    except KeyboardInterrupt:
        print("\nAssessment interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error during assessment: {e}", file=sys.stderr)
        import traceback
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)
    
    # Generate reports
    try:
        # Print human-readable report
        reporter.print_report(assessment, verbose=args.verbose)
        
        # Save JSON if requested
        if args.json:
            reporter.save_json_report(assessment, args.json)
            print(f"JSON report saved to: {args.json}")
        
        # Exit code based on findings
        summary = assessment['summary']
        if summary['high_severity'] > 0:
            sys.exit(2)  # High severity findings
        elif summary['warn_severity'] > 0:
            sys.exit(1)  # Warnings
        else:
            sys.exit(0)  # No issues
        
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
