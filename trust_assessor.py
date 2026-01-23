"""
Trust Assessment Module

Correlates SSH configuration, host keys, SSHFP records, and DNSSEC
validation to assess trust establishment security.

LIMITATIONS:
- Focus is on misconfiguration detection, not runtime attack detection
- SSH certificates are not analyzed (focus is on host key verification via SSHFP)
- DNSSEC validation status is based on AD flag (operational signal, not cryptographic proof)
- This tool does not perform cryptographic validation of DNSSEC signatures
- Analysis is read-only and does not modify system state
"""

from typing import List, Dict, Optional
from ssh_config_parser import SSHConfigParser
from host_key_analyzer import HostKeyAnalyzer
from dns_sshfp_query import SSHFPQuery
from dnssec_validator import DNSSECValidator


class TrustAssessor:
    """Assess SSH trust establishment security."""
    
    def __init__(self, ssh_config_path: str = '/etc/ssh/sshd_config',
                 host_key_dir: str = '/etc/ssh',
                 resolver_ip: Optional[str] = None):
        """
        Initialize the trust assessor.
        
        Args:
            ssh_config_path: Path to sshd_config
            host_key_dir: Directory containing SSH host keys
            resolver_ip: Custom DNS resolver IP
        """
        self.ssh_config_parser = SSHConfigParser(ssh_config_path)
        self.host_key_analyzer = HostKeyAnalyzer(host_key_dir)
        self.sshfp_query = SSHFPQuery(resolver_ip)
        self.dnssec_validator = DNSSECValidator(resolver_ip)
    
    def assess_host(self, hostname: str) -> Dict:
        """
        Perform complete trust assessment for a hostname.
        
        Args:
            hostname: Hostname to assess
            
        Returns:
            Dictionary containing assessment results and findings
        """
        findings = []
        
        # 1. Parse SSH configuration
        # SSH configuration reveals trust-relevant settings that affect how
        # clients establish trust with the server
        try:
            ssh_config = self.ssh_config_parser.parse()
            trust_directives = self.ssh_config_parser.get_trust_relevant_directives()
        except PermissionError as e:
            findings.append({
                'severity': 'WARN',
                'title': 'SSH Configuration Access Denied',
                'description': f'Cannot read SSH configuration file: {e}',
                'reason': 'Insufficient permissions to read sshd_config. Run with appropriate privileges or specify a readable copy with --ssh-config.',
            })
            ssh_config = {}
            trust_directives = {}
        except Exception as e:
            findings.append({
                'severity': 'WARN',
                'title': 'SSH Configuration Parse Error',
                'description': f'Failed to parse SSH configuration: {str(e)}',
                'reason': 'Configuration file may be malformed or inaccessible. Check file path and permissions.',
            })
            ssh_config = {}
            trust_directives = {}
        
        # 2. Discover host keys
        # Host keys are used for server authentication. Their fingerprints
        # must match SSHFP records in DNS for secure verification
        try:
            host_keys = self.host_key_analyzer.discover_host_keys()
            sshfp_from_keys = self.host_key_analyzer.get_sshfp_records()
        except PermissionError as e:
            findings.append({
                'severity': 'WARN',
                'title': 'Host Key Access Denied',
                'description': f'Cannot read SSH host keys: {e}',
                'reason': 'Insufficient permissions to read host key directory. Run with appropriate privileges or specify a readable copy with --host-key-dir.',
            })
            host_keys = []
            sshfp_from_keys = []
        except Exception as e:
            findings.append({
                'severity': 'WARN',
                'title': 'Host Key Discovery Error',
                'description': f'Failed to discover host keys: {str(e)}',
                'reason': 'Host key directory may be inaccessible or invalid. Check directory path and permissions.',
            })
            host_keys = []
            sshfp_from_keys = []
        
        # 3. Query DNS for SSHFP records
        # SSHFP records publish host key fingerprints in DNS, enabling
        # clients to verify server identity without TOFU
        try:
            sshfp_records = self.sshfp_query.query_sshfp(hostname)
        except Exception as e:
            findings.append({
                'severity': 'WARN',
                'title': 'SSHFP DNS Query Error',
                'description': f'Failed to query SSHFP records for {hostname}: {str(e)}',
                'reason': 'DNS query failed. Check network connectivity, DNS resolver configuration, and hostname resolution.',
            })
            sshfp_records = []
        
        # 4. Check DNSSEC validation
        # DNSSEC validation ensures SSHFP records are authentic and prevents
        # DNS spoofing attacks. Only checked when SSHFP records exist.
        dnssec_status = None
        if sshfp_records:  # Only check DNSSEC if SSHFP records exist
            try:
                dnssec_status = self.dnssec_validator.check_dnssec_validation(hostname, 'SSHFP')
            except Exception as e:
                findings.append({
                    'severity': 'WARN',
                    'title': 'DNSSEC Validation Check Error',
                    'description': f'Failed to check DNSSEC validation: {str(e)}',
                    'reason': 'DNSSEC validation check failed. Ensure validating resolver is configured correctly and network connectivity is available.',
                })
                dnssec_status = {
                    'status': 'error',
                    'description': f'Error: {str(e)}',
                    'ad_flag': False,
                }
        else:
            # No DNSSEC check needed if no SSHFP records
            dnssec_status = {
                'status': 'unknown',
                'description': 'DNSSEC check skipped (no SSHFP records)',
                'ad_flag': False,
            }
        
        # 5. Correlate and assess trust
        
        # Check: SSHFP records exist
        if not sshfp_records:
            findings.append({
                'severity': 'HIGH',
                'title': 'No SSHFP Records Found',
                'description': f'No SSHFP DNS records found for {hostname}',
                'reason': 'SSH host verification relies on TOFU (Trust On First Use) without DNS-based verification. This means clients must accept the host key on first connection without cryptographic verification via DNS.',
                'remediation': 'Publish SSHFP records in DNS for all host keys',
            })
        else:
            findings.append({
                'severity': 'INFO',
                'title': 'SSHFP Records Found',
                'description': f'Found {len(sshfp_records)} SSHFP record(s) for {hostname}',
                'reason': 'DNS-based host key verification is configured',
            })
            
            # DNSSEC validation findings ONLY when SSHFP records exist
            # This avoids logically invalid findings when SSHFP is not configured
            if dnssec_status['status'] == 'validated':
                findings.append({
                    'severity': 'INFO',
                    'title': 'DNSSEC Validation Successful',
                    'description': 'SSHFP records are DNSSEC validated',
                    'reason': 'DNS responses are authenticated via DNSSEC, preventing DNS spoofing attacks. The AD (Authenticated Data) flag indicates the validating resolver successfully validated the response.',
                })
            elif dnssec_status['status'] == 'not_validated':
                findings.append({
                    'severity': 'HIGH',
                    'title': 'DNSSEC Validation Failed or Not Available',
                    'description': 'SSHFP records exist but are not DNSSEC validated',
                    'reason': 'SSHFP records can be spoofed via DNS attacks without DNSSEC validation. An attacker could inject malicious SSHFP records through DNS cache poisoning or man-in-the-middle attacks.',
                    'remediation': 'Enable DNSSEC validation on the DNS resolver and ensure DNS zone is signed',
                })
            elif dnssec_status['status'] == 'unknown':
                findings.append({
                    'severity': 'WARN',
                    'title': 'DNSSEC Validation Status Unknown',
                    'description': 'Could not determine DNSSEC validation status',
                    'reason': 'DNSSEC validation check returned unknown status. This may indicate the resolver does not support DNSSEC validation or the query failed.',
                })
            # Note: 'error' status is handled by the exception handler above
        
        # Check: SSHFP fingerprint matching
        if sshfp_records and sshfp_from_keys:
            matched_keys = []
            unmatched_sshfp = []
            
            for sshfp in sshfp_records:
                # Try to match this SSHFP record with a host key
                match = self.host_key_analyzer.match_sshfp(
                    sshfp['algorithm'],
                    sshfp['fingerprint_type'],
                    sshfp['fingerprint']
                )
                
                if match:
                    matched_keys.append({
                        'sshfp': sshfp,
                        'host_key': match,
                    })
                else:
                    unmatched_sshfp.append(sshfp)
            
            if matched_keys:
                findings.append({
                    'severity': 'INFO',
                    'title': 'SSHFP Fingerprints Match Host Keys',
                    'description': f'{len(matched_keys)} SSHFP record(s) match actual host key(s)',
                    'reason': 'DNS-published fingerprints match server host keys',
                })
            
            if unmatched_sshfp:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'SSHFP Fingerprint Mismatch',
                    'description': f'{len(unmatched_sshfp)} SSHFP record(s) do not match any host key',
                    'reason': 'DNS-published fingerprints do not match actual server host keys, indicating misconfiguration or key rotation',
                    'remediation': 'Update SSHFP records in DNS to match current host keys',
                })
        elif sshfp_records and not sshfp_from_keys:
            findings.append({
                'severity': 'WARN',
                'title': 'Cannot Verify SSHFP Fingerprints',
                'description': 'SSHFP records found but host keys could not be read',
                'reason': 'Unable to compare SSHFP records with actual host keys',
            })
        
        # Check: UseDNS directive
        use_dns = ssh_config.get('UseDNS', 'yes').lower()
        if use_dns == 'no':
            findings.append({
                'severity': 'INFO',
                'title': 'UseDNS Disabled',
                'description': 'SSH server has UseDNS disabled',
                'reason': 'SSH server will not perform DNS lookups (may affect SSHFP usage)',
            })
        
        # Check: Trust-relevant configuration
        if trust_directives:
            # Check for insecure configurations
            if trust_directives.get('PasswordAuthentication', 'yes').lower() == 'yes':
                findings.append({
                    'severity': 'WARN',
                    'title': 'Password Authentication Enabled',
                    'description': 'Password authentication is enabled',
                    'reason': 'Password authentication is less secure than key-based authentication',
                })
            
            if trust_directives.get('PermitRootLogin', 'prohibit-password').lower() == 'yes':
                findings.append({
                    'severity': 'HIGH',
                    'title': 'Root Login Permitted',
                    'description': 'Root login is permitted (may allow password authentication)',
                    'reason': 'Permitting root login increases security risk',
                })
        
        # Compile assessment summary
        assessment = {
            'hostname': hostname,
            'ssh_config': {
                'parsed': bool(ssh_config),
                'trust_directives': trust_directives,
            },
            'host_keys': {
                'count': len(host_keys),
                'keys': [{'algorithm': k['algorithm'], 'file': k['file']} for k in host_keys],
            },
            'sshfp_records': {
                'count': len(sshfp_records),
                'records': sshfp_records,
            },
            'dnssec_validation': dnssec_status,
            'findings': findings,
            'summary': self._generate_summary(findings),
        }
        
        return assessment
    
    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """
        Generate a summary of findings by severity.
        
        Args:
            findings: List of findings
            
        Returns:
            Summary dictionary
        """
        summary = {
            'total_findings': len(findings),
            'high_severity': len([f for f in findings if f['severity'] == 'HIGH']),
            'warn_severity': len([f for f in findings if f['severity'] == 'WARN']),
            'info_severity': len([f for f in findings if f['severity'] == 'INFO']),
            'overall_status': 'unknown',
        }
        
        if summary['high_severity'] > 0:
            summary['overall_status'] = 'insecure'
        elif summary['warn_severity'] > 0:
            summary['overall_status'] = 'warning'
        else:
            summary['overall_status'] = 'secure'
        
        return summary
