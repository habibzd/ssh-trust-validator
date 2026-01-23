"""
DNS SSHFP Query Module

Queries DNS for SSHFP records and extracts relevant information.
Uses dnspython library for DNS operations.

LIMITATIONS:
- Does not validate DNS response authenticity (relies on DNSSEC validator module)
- Does not handle DNS over HTTPS (DoH) or DNS over TLS (DoT)
- Focus is on extracting SSHFP record data for comparison
"""

import dns.resolver
import dns.exception
from typing import List, Dict, Optional


class SSHFPQuery:
    """Query DNS for SSHFP records."""
    
    # SSHFP algorithm numbers (RFC 4255)
    # Note: Algorithm 3 represents all ECDSA variants (nistp256, nistp384, nistp521)
    # The specific curve is identified by the key data, not the algorithm number
    SSHFP_ALGORITHMS = {
        1: 'RSA',
        2: 'DSA',
        3: 'ECDSA',  # All ECDSA curves (nistp256, nistp384, nistp521) use algorithm 3
        4: 'Reserved',  # Not used in current RFC 4255
        5: 'Reserved',  # Not used in current RFC 4255
        6: 'Ed25519',
        7: 'Ed448',
    }
    
    # SSHFP fingerprint types
    SSHFP_FPTYPE_SHA1 = 1
    SSHFP_FPTYPE_SHA256 = 2
    
    def __init__(self, resolver_ip: Optional[str] = None):
        """
        Initialize the SSHFP query module.
        
        Args:
            resolver_ip: Custom DNS resolver IP address (optional)
        """
        self.resolver_ip = resolver_ip
        self.resolver = dns.resolver.Resolver()
        
        if resolver_ip:
            self.resolver.nameservers = [resolver_ip]
    
    def query_sshfp(self, hostname: str) -> List[Dict]:
        """
        Query DNS for SSHFP records for a given hostname.
        
        Args:
            hostname: Hostname to query (without trailing dot)
            
        Returns:
            List of dictionaries containing SSHFP record information
        """
        sshfp_records = []
        
        try:
            # Query for SSHFP records
            answers = self.resolver.resolve(hostname, 'SSHFP', raise_on_no_answer=False)
            
            for answer in answers:
                # Parse SSHFP record
                # Format: <algorithm> <fingerprint_type> <fingerprint>
                parts = str(answer).split()
                if len(parts) < 3:
                    continue
                
                try:
                    algorithm = int(parts[0])
                    fingerprint_type = int(parts[1])
                    fingerprint = parts[2]
                    
                    sshfp_record = {
                        'algorithm': algorithm,
                        'algorithm_name': self.SSHFP_ALGORITHMS.get(algorithm, f'Unknown({algorithm})'),
                        'fingerprint_type': fingerprint_type,
                        'fingerprint_type_name': 'SHA1' if fingerprint_type == 1 else 'SHA256',
                        'fingerprint': fingerprint,
                        'hostname': hostname,
                        'raw_record': str(answer),
                    }
                    
                    sshfp_records.append(sshfp_record)
                    
                except (ValueError, IndexError) as e:
                    # Skip malformed records
                    continue
                    
        except dns.resolver.NXDOMAIN:
            # Hostname doesn't exist
            return []
        except dns.resolver.NoAnswer:
            # No SSHFP records found
            return []
        except dns.exception.DNSException as e:
            # Other DNS errors
            raise DNSQueryError(f"DNS query failed for {hostname}: {e}")
        
        return sshfp_records
    
    def query_a_record(self, hostname: str) -> List[str]:
        """
        Query DNS for A records (for validation purposes).
        
        Args:
            hostname: Hostname to query
            
        Returns:
            List of IP addresses
        """
        try:
            answers = self.resolver.resolve(hostname, 'A')
            return [str(answer) for answer in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.exception.DNSException as e:
            raise DNSQueryError(f"DNS A record query failed for {hostname}: {e}")


class DNSQueryError(Exception):
    """Exception raised for DNS query errors."""
    pass
