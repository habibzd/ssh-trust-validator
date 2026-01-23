"""
SSH Configuration Parser Module

Parses OpenSSH server configuration files (sshd_config) with support for:
- Include directives (processed inline, matching OpenSSH behavior)
- Comment and blank line handling
- OpenSSH precedence rules (last value wins)
- Trust-relevant directive extraction

LIMITATIONS:
- Does not validate configuration syntax beyond basic parsing
- Does not check for conflicting or invalid directive combinations
- Focus is on extracting trust-relevant settings, not full configuration validation
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class SSHConfigParser:
    """Parser for OpenSSH server configuration files."""
    
    # Trust-relevant directives to extract
    TRUST_RELEVANT_DIRECTIVES = [
        'PasswordAuthentication',
        'PermitRootLogin',
        'PubkeyAuthentication',
        'HostKey',
        'UseDNS',
        'StrictModes',
        'PermitEmptyPasswords',
        'ChallengeResponseAuthentication',
        'GSSAPIAuthentication',
        'HostbasedAuthentication',
        'IgnoreRhosts',
        'IgnoreUserKnownHosts',
        'PermitUserEnvironment',
        'X11Forwarding',
        'AllowTcpForwarding',
    ]
    
    def __init__(self, config_path: str = '/etc/ssh/sshd_config'):
        """
        Initialize the SSH config parser.
        
        Args:
            config_path: Path to the main sshd_config file
        """
        self.config_path = Path(config_path)
        self.config_dir = self.config_path.parent
        self.directives: Dict[str, List[str]] = {}
        
    def parse(self) -> Dict[str, str]:
        """
        Parse the SSH configuration file and included files.
        
        This method processes Include directives inline (at the point they appear),
        matching OpenSSH behavior. Included file lines are injected in-place,
        preserving the order of processing.
        
        Returns:
            Dictionary mapping directive names to their final values
            (following OpenSSH precedence: last value wins)
        """
        # Process configuration with inline Include handling
        all_lines = self._parse_with_includes(self.config_path)
        
        # Extract directives (last value wins)
        final_directives = {}
        for line in all_lines:
            directive, value = self._parse_line(line)
            if directive:
                final_directives[directive] = value
        
        self.directives = final_directives
        return final_directives
    
    def _parse_with_includes(self, file_path: Path) -> List[str]:
        """
        Parse a configuration file, processing Include directives inline.
        
        When an Include directive is encountered, the included files are
        processed immediately and their lines are inserted at that point.
        This matches OpenSSH behavior where Include directives are processed
        at the point they appear in the configuration.
        
        Args:
            file_path: Path to the configuration file to parse
            
        Returns:
            List of configuration lines with includes processed inline
        """
        all_lines = []
        
        if not file_path.exists():
            return all_lines
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    # Remove comments (everything after #, but not escaped #)
                    clean_line = re.sub(r'(?<!\\)#.*$', '', line)
                    clean_line = clean_line.strip()
                    
                    # Skip blank lines
                    if not clean_line:
                        continue
                    
                    # Check if this is an Include directive
                    include_match = re.match(r'^\s*[Ii]nclude\s+(.+)$', clean_line)
                    if include_match:
                        # Process Include directive inline
                        pattern = include_match.group(1).strip()
                        pattern = pattern.strip('"\'')
                        
                        # Process included files and insert their lines here
                        included_lines = self._process_include_pattern(pattern)
                        all_lines.extend(included_lines)
                    else:
                        # Regular configuration line
                        all_lines.append(clean_line)
                        
        except PermissionError:
            raise PermissionError(f"Permission denied reading {file_path}")
        except FileNotFoundError:
            return []
        except Exception as e:
            raise IOError(f"Error reading {file_path}: {e}")
        
        return all_lines
    
    
    def _process_include_pattern(self, pattern: str) -> List[str]:
        """
        Process an Include pattern and return matching file contents.
        
        This method recursively processes included files, so nested Includes
        are supported. Files are processed in sorted order for deterministic
        behavior with glob patterns.
        
        Args:
            pattern: Include pattern (may contain wildcards)
            
        Returns:
            List of configuration lines from matching files (with nested Includes processed)
        """
        lines = []
        
        # Resolve relative paths
        if not os.path.isabs(pattern):
            pattern = str(self.config_dir / pattern)
        else:
            pattern = str(Path(pattern))
        
        # Handle wildcards
        if '*' in pattern or '?' in pattern:
            # Use glob to find matching files
            from glob import glob
            matching_files = glob(pattern, recursive=True)
            for file_path in sorted(matching_files):
                file_path = Path(file_path)
                if file_path.is_file():
                    # Recursively process included file (handles nested Includes)
                    lines.extend(self._parse_with_includes(file_path))
        else:
            # Single file
            file_path = Path(pattern)
            if file_path.is_file():
                # Recursively process included file (handles nested Includes)
                lines.extend(self._parse_with_includes(file_path))
        
        return lines
    
    def _parse_line(self, line: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parse a single configuration line.
        
        Args:
            line: Configuration line
            
        Returns:
            Tuple of (directive_name, value) or (None, None) if not a directive
        """
        # Match directive = value or directive value
        match = re.match(r'^\s*(\w+)\s+(?:=\s*)?(.+)$', line)
        if match:
            directive = match.group(1)
            value = match.group(2).strip()
            # Remove quotes if present
            value = value.strip('"\'')
            return directive, value
        
        return None, None
    
    def get_trust_relevant_directives(self) -> Dict[str, str]:
        """
        Get only trust-relevant directives from the parsed configuration.
        
        Returns:
            Dictionary of trust-relevant directives
        """
        if not self.directives:
            self.parse()
        
        trust_directives = {}
        for directive in self.TRUST_RELEVANT_DIRECTIVES:
            if directive in self.directives:
                trust_directives[directive] = self.directives[directive]
        
        return trust_directives
    
    def get_directive(self, directive: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a specific directive value.
        
        Args:
            directive: Directive name
            default: Default value if directive not found
            
        Returns:
            Directive value or default
        """
        if not self.directives:
            self.parse()
        
        return self.directives.get(directive, default)
