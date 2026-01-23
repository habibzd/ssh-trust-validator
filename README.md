# SSH Trust Validator

A Python-based automated validation tool that analyses SSH trust establishment by correlating SSH server configuration, SSH host keys, DNS-based host key verification (SSHFP), and DNSSEC validation status.

## Overview

This tool detects insecure trust assumptions in SSH configurations, particularly:

- **Trust On First Use (TOFU)** reliance without external validation
- **SSHFP records** used without proper DNSSEC validation
- **Mismatched fingerprints** between DNS records and actual host keys
- **Misconfigured SSH settings** that weaken trust establishment

The tool is designed for **read-only analysis** in lab environments and does not modify system state or exploit vulnerabilities.

## Features

- ✅ Parses OpenSSH `sshd_config` with Include directive support
- ✅ Extracts SSH host key fingerprints (SHA256)
- ✅ Queries DNS for SSHFP records
- ✅ Detects DNSSEC validation status (AD flag)
- ✅ Correlates all inputs to assess trust security
- ✅ Generates clear findings with severity levels
- ✅ Supports human-readable and JSON output formats

## Installation

### Prerequisites

- Python 3.7 or higher
- Access to SSH server configuration and host keys (typically requires root/sudo)
- Network access to DNS resolver

### Setup

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Assess a hostname (default paths):
```bash
python main.py example.com
```

### Custom DNS Resolver

Specify a validating resolver:
```bash
python main.py example.com --resolver 192.168.1.100
```

### Custom SSH Configuration Path

```bash
python main.py example.com --ssh-config /custom/path/sshd_config
```

### Custom Host Key Directory

```bash
python main.py example.com --host-key-dir /custom/path/ssh
```

### Generate JSON Report

```bash
python main.py example.com --json report.json
```

### Verbose Output

Show detailed information:
```bash
python main.py example.com --verbose
```

### Disable Colored Output

```bash
python main.py example.com --no-color
```

## Lab Environment Setup

This tool is designed for a lab environment with four VMs:

1. **SSH Server VM**
   - Runs OpenSSH with real `sshd_config`
   - Has host keys in `/etc/ssh/`

2. **Authoritative DNS Server VM**
   - Publishes A records and SSHFP records
   - DNSSEC may be enabled or disabled

3. **Validating Resolver VM**
   - Performs DNSSEC validation
   - Sets AD flag when validation succeeds

4. **Client / Analysis VM**
   - Runs this validation tool
   - Queries DNS through the validating resolver

## Output

### Human-Readable Report

The tool generates a structured report with:
- **Summary**: Overall status and finding counts
- **Findings**: Detailed issues grouped by severity (HIGH, WARN, INFO)
- **Configuration Details**: SSH config, host keys, SSHFP records, DNSSEC status (verbose mode)

### JSON Report

JSON output includes:
- Complete assessment data
- All findings with severity and remediation suggestions
- Raw configuration and DNS data

### Exit Codes

- `0`: No issues found
- `1`: Warnings present
- `2`: High severity findings

## Example Output

```
================================================================================
SSH Trust Assessment Report: example.com
================================================================================

[SUMMARY]
  Overall Status: INSECURE
  Total Findings: 4
    - HIGH: 2
    - WARN: 1
    - INFO: 1

[FINDINGS]

  [HIGH] No SSHFP Records Found
      Description: No SSHFP DNS records found for example.com
      Reason: SSH host verification relies on TOFU (Trust On First Use) without DNS-based verification
      Remediation: Publish SSHFP records in DNS for all host keys

  [HIGH] DNSSEC Validation Failed or Not Available
      Description: SSHFP records exist but are not DNSSEC validated
      Reason: SSHFP records can be spoofed via DNS attacks without DNSSEC validation
      Remediation: Enable DNSSEC validation on the DNS resolver and ensure DNS zone is signed

...
```

## Security & Ethics

This tool is designed for:
- ✅ **Read-only analysis** - No system modification
- ✅ **Lab environments** - Controlled testing scenarios
- ✅ **Misconfiguration detection** - Not exploitation
- ✅ **Educational purposes** - Undergraduate cybersecurity projects

The tool does NOT:
- ❌ Modify system state
- ❌ Exploit vulnerabilities
- ❌ Perform brute force attacks
- ❌ Inject network traffic

## Project Structure

```
ssh-trust-validator/
├── main.py                 # CLI entry point
├── ssh_config_parser.py     # SSH configuration parsing
├── host_key_analyzer.py     # Host key fingerprint extraction
├── dns_sshfp_query.py      # DNS SSHFP record querying
├── dnssec_validator.py     # DNSSEC validation detection
├── trust_assessor.py        # Core trust assessment logic
├── reporter.py              # Report generation
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Technical Details

### SSH Configuration Parsing

- Supports Include directives (`/etc/ssh/sshd_config.d/*.conf`)
- Follows OpenSSH precedence rules (last value wins)
- Handles comments and blank lines
- Extracts trust-relevant directives

### Host Key Analysis

- Supports modern key types (Ed25519, ECDSA, RSA)
- Generates SHA256 fingerprints
- Compatible with SSHFP record format

### DNSSEC Validation

- Uses AD (Authenticated Data) flag as validation signal
- Queries through validating resolver
- Distinguishes validated, not validated, and unknown states

### Trust Assessment

The tool correlates:
1. SSH configuration settings
2. Actual host key fingerprints
3. DNS SSHFP records
4. DNSSEC validation status

To detect:
- Missing SSHFP records (TOFU reliance)
- SSHFP without DNSSEC (spoofable)
- Fingerprint mismatches (misconfiguration)
- Secure configurations (SSHFP + DNSSEC + matching fingerprints)

## Troubleshooting

### Permission Denied

If you get permission errors reading SSH configuration or host keys:
- Run with appropriate permissions (sudo/root)
- Or copy files to a readable location and use `--ssh-config` and `--host-key-dir`

### DNS Query Failures

- Ensure network connectivity
- Check DNS resolver configuration
- Verify hostname resolves correctly

### DNSSEC Validation Unknown

- Ensure you're using a validating resolver (`--resolver`)
- Check that DNSSEC is properly configured in your lab environment

## License

This project is designed for educational purposes as part of an undergraduate cybersecurity project.

## Author

Created for an undergraduate artefact-driven cybersecurity project focused on SSH trust misconfiguration detection.
