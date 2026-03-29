"""
DNSSEC Validation Detection Module

Detects whether DNS responses are DNSSEC validated by checking
the AD (Authenticated Data) flag in DNS responses.

LIMITATIONS:
- The AD flag is an operational signal from the validating resolver, not cryptographic proof
- This module does not perform DNSSEC cryptographic validation itself
- It relies on the resolver's validation status as indicated by the AD flag
- SSH certificates are not analyzed (focus is on host key verification via SSHFP)
- This tool focuses on misconfiguration detection, not runtime attack detection
"""

import socket
import dns.message
import dns.flags
import dns.rcode
import dns.resolver
from typing import Optional, Dict


class DNSSECValidator:
    """
    Detect DNSSEC validation status from DNS responses.

    Sends a raw UDP query with the DO flag set directly to the configured resolver
    and checks the AD (Authenticated Data) flag in the response. The AD flag is an
    operational signal that indicates the validating resolver successfully validated
    the response using DNSSEC.
    """
    
    def __init__(self, resolver_ip: Optional[str] = None):
        """
        Initialize the DNSSEC validator.
        
        Args:
            resolver_ip: Custom DNS resolver IP address (validating resolver)
        """
        self.resolver_ip = resolver_ip
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 10

        if resolver_ip:
            self.resolver.nameservers = [resolver_ip]

        print(f"[DEBUG] DNSSECValidator init: resolver_ip={resolver_ip}, nameservers={self.resolver.nameservers}")
    
    def check_dnssec_validation(self, hostname: str, record_type: str = 'SSHFP') -> Dict:
        """
        Check if DNS responses for a hostname are DNSSEC validated.

        Sends a raw UDP query with the DO flag directly to the configured resolver
        and checks the AD flag in the response.

        Args:
            hostname: Hostname to check
            record_type: DNS record type to query (default: SSHFP)
            
        Returns:
            Dictionary with DNSSEC validation status:
            {
                "status": "validated | not_validated | unknown | error",
                "description": "...",
                "ad_flag": true/false,
                "hostname": "...",
                "record_type": "SSHFP",
                "resolver_ip": "..."
            }
        """
        try:
            resolver_addr = self.resolver_ip or (self.resolver.nameservers[0] if self.resolver.nameservers else None)
            if not resolver_addr:
                raise DNSSECValidationError("No DNS resolver configured")

            # Build query with DO flag set to request DNSSEC validation
            query = dns.message.make_query(hostname, record_type)
            query.flags |= dns.flags.DO

            print(f"[DEBUG] Sending DNSSEC UDP query for {hostname} {record_type} to {resolver_addr}:53")

            # Use a raw socket instead of dns.query.udp() to avoid the
            # BlockingIOError (EAGAIN) caused by dnspython setting non-blocking mode
            wire = query.to_wire()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            try:
                sock.sendto(wire, (resolver_addr, 53))
                data, _ = sock.recvfrom(4096)
            finally:
                sock.close()

            response = dns.message.from_wire(data)
            print(f"[DEBUG] Response received from {resolver_addr}, flags={dns.flags.to_text(response.flags)}")

            if response.rcode() == dns.rcode.NXDOMAIN:
                return {
                    'status': 'error',
                    'description': 'Hostname does not exist (NXDOMAIN)',
                    'ad_flag': False,
                    'hostname': hostname,
                    'record_type': record_type,
                    'resolver_ip': resolver_addr,
                }

            # Check AD (Authenticated Data) flag using explicit integer bitmask.
            # dns.flags.AD = 0x0020 (32). Cast both sides to int to avoid
            # any IntFlag enum comparison ambiguity across dnspython versions.
            ad_flag_set = bool(int(response.flags) & int(dns.flags.AD))

            # Determine validation status based on AD flag
            if ad_flag_set:
                status = 'validated'
                description = 'DNSSEC validation successful (AD flag set by validating resolver)'
            else:
                # AD flag not set - check if records were returned at all
                if len(response.answer) > 0:
                    status = 'not_validated'
                    description = 'DNS records exist but DNSSEC validation failed or not available (AD flag not set)'
                else:
                    status = 'unknown'
                    description = 'No DNS records found, DNSSEC validation status unknown'
            
            result = {
                'status': status,
                'description': description,
                'ad_flag': ad_flag_set,
                'hostname': hostname,
                'record_type': record_type,
                'resolver_ip': resolver_addr,
            }
            
            return result
            
        except dns.exception.Timeout:
            raise DNSSECValidationError(f"DNS query timeout for {hostname}")
        except Exception as e:
            raise DNSSECValidationError(f"DNSSEC validation check failed for {hostname}: {e}")
    
    def is_validated(self, hostname: str, record_type: str = 'SSHFP') -> bool:
        """
        Simple check: returns True if DNSSEC validation succeeded.
        
        Args:
            hostname: Hostname to check
            record_type: DNS record type to query
            
        Returns:
            True if DNSSEC validated, False otherwise
        """
        result = self.check_dnssec_validation(hostname, record_type)
        return result['status'] == 'validated'


class DNSSECValidationError(Exception):
    """Exception raised for DNSSEC validation errors."""
    pass
