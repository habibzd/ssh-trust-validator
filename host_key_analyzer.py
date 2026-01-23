"""
SSH Host Key Analyzer Module

Extracts and analyzes SSH host public keys, generating fingerprints
compatible with SSHFP DNS records.

LIMITATIONS:
- Only analyzes host keys, not SSH certificates
- Focus is on fingerprint generation for SSHFP comparison
- Does not validate key strength or cryptographic properties
"""

import hashlib
import base64
from pathlib import Path
from typing import List, Dict, Optional


class HostKeyAnalyzer:
    """Analyzer for SSH host public keys."""
    
    # SSHFP algorithm numbers (RFC 4255)
    # Note: All ECDSA variants (nistp256, nistp384, nistp521) map to algorithm 3
    # The curve information is not part of the SSHFP algorithm number
    SSHFP_ALGORITHMS = {
        'ssh-rsa': 1,
        'ssh-dss': 2,
        'ecdsa-sha2-nistp256': 3,  # All ECDSA variants use algorithm 3
        'ecdsa-sha2-nistp384': 3,  # RFC 4255 specifies algorithm 3 for ECDSA
        'ecdsa-sha2-nistp521': 3,  # Curve is identified by the key data, not algorithm number
        'ssh-ed25519': 6,
        'ssh-ed448': 7,
    }
    
    # SSHFP fingerprint types
    SSHFP_FPTYPE_SHA1 = 1
    SSHFP_FPTYPE_SHA256 = 2
    
    def __init__(self, host_key_dir: str = '/etc/ssh'):
        """
        Initialize the host key analyzer.
        
        Args:
            host_key_dir: Directory containing SSH host keys
        """
        self.host_key_dir = Path(host_key_dir)
        self.host_keys: List[Dict] = []
        
    def discover_host_keys(self) -> List[Dict]:
        """
        Discover all SSH host public keys in the configured directory.
        
        Returns:
            List of dictionaries containing host key information
        """
        host_keys = []
        
        if not self.host_key_dir.exists():
            return host_keys
        
        # Find all ssh_host_*_key.pub files
        pattern = 'ssh_host_*_key.pub'
        for key_file in self.host_key_dir.glob(pattern):
            try:
                key_info = self._parse_host_key_file(key_file)
                if key_info:
                    host_keys.append(key_info)
            except Exception as e:
                # Log error but continue with other keys
                print(f"Warning: Failed to parse {key_file}: {e}")
        
        self.host_keys = host_keys
        return host_keys
    
    def _parse_host_key_file(self, key_file: Path) -> Optional[Dict]:
        """
        Parse a single SSH host public key file.
        
        Args:
            key_file: Path to the public key file
            
        Returns:
            Dictionary with key information or None if parsing fails
        """
        try:
            with open(key_file, 'r', encoding='utf-8') as f:
                line = f.readline().strip()
            
            # Parse SSH public key format: <algorithm> <base64_key> [comment]
            parts = line.split()
            if len(parts) < 2:
                return None
            
            algorithm = parts[0]
            base64_key = parts[1]
            
            # Decode the key
            try:
                key_bytes = base64.b64decode(base64_key)
            except Exception:
                return None
            
            # Generate fingerprints
            sha256_fp = hashlib.sha256(key_bytes).digest()
            sha256_hex = sha256_fp.hex()
            sha256_base64 = base64.b64encode(sha256_fp).decode('ascii')
            
            # Get SSHFP algorithm number
            sshfp_algorithm = self.SSHFP_ALGORITHMS.get(algorithm, None)
            
            key_info = {
                'file': str(key_file),
                'algorithm': algorithm,
                'sshfp_algorithm': sshfp_algorithm,
                'fingerprint_sha256_hex': sha256_hex,
                'fingerprint_sha256_base64': sha256_base64,
                'fingerprint_sha256_bytes': sha256_fp,
            }
            
            return key_info
            
        except PermissionError:
            raise PermissionError(f"Permission denied reading {key_file}")
        except Exception as e:
            raise IOError(f"Error reading {key_file}: {e}")
    
    def get_sshfp_records(self) -> List[Dict]:
        """
        Generate SSHFP record data for all discovered host keys.
        
        Returns:
            List of dictionaries with SSHFP record information
        """
        if not self.host_keys:
            self.discover_host_keys()
        
        sshfp_records = []
        for key_info in self.host_keys:
            if key_info['sshfp_algorithm'] is None:
                continue
            
            sshfp_record = {
                'algorithm': key_info['sshfp_algorithm'],
                'fingerprint_type': self.SSHFP_FPTYPE_SHA256,
                'fingerprint': key_info['fingerprint_sha256_hex'],
                'key_algorithm': key_info['algorithm'],
                'source_file': key_info['file'],
            }
            sshfp_records.append(sshfp_record)
        
        return sshfp_records
    
    def match_sshfp(self, sshfp_algorithm: int, fingerprint_type: int, 
                   fingerprint: str) -> Optional[Dict]:
        """
        Check if a given SSHFP record matches any discovered host key.
        
        Args:
            sshfp_algorithm: SSHFP algorithm number
            fingerprint_type: SSHFP fingerprint type (1=SHA1, 2=SHA256)
            fingerprint: Fingerprint value (hex string)
            
        Returns:
            Matching host key info or None
        """
        if not self.host_keys:
            self.discover_host_keys()
        
        # Normalize fingerprint (lowercase, remove colons/spaces)
        fingerprint = fingerprint.lower().replace(':', '').replace(' ', '')
        
        for key_info in self.host_keys:
            if key_info['sshfp_algorithm'] != sshfp_algorithm:
                continue
            
            if fingerprint_type == self.SSHFP_FPTYPE_SHA256:
                key_fp = key_info['fingerprint_sha256_hex'].lower()
            else:
                # SHA1 not supported in this implementation
                continue
            
            if key_fp == fingerprint:
                return key_info
        
        return None
