"""
SSH Trust Validator

A Python-based automated validation tool that analyses SSH trust establishment
by correlating SSH server configuration, SSH host keys, DNS-based host key
verification (SSHFP), and DNSSEC validation status.
"""

__version__ = '1.0.0'

from .ssh_config_parser import SSHConfigParser
from .host_key_analyzer import HostKeyAnalyzer
from .dns_sshfp_query import SSHFPQuery
from .dnssec_validator import DNSSECValidator
from .trust_assessor import TrustAssessor
from .reporter import Reporter

__all__ = [
    'SSHConfigParser',
    'HostKeyAnalyzer',
    'SSHFPQuery',
    'DNSSECValidator',
    'TrustAssessor',
    'Reporter',
]
