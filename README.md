# SSH Trust Validator

This project is a Python-based validation tool that checks whether SSH host trust is being established securely.
It focuses on detecting misconfiguration in SSH trust mechanisms, particularly around SSHFP records and DNSSEC validation.
The tool does not scan for vulnerabilities or CVEs. It evaluates configuration and trust state consistency.

# What Problem This Addresses

SSH commonly relies on Trust On First Use (TOFU), where the first connection pins a host key without independent verification. This can be risky if DNS-based verification is misconfigured or if DNSSEC is not properly validated.
This tool checks whether:

SSHFP records exist in DNS
SSHFP fingerprints match the server’s actual host keys
DNSSEC validation is present
SSH configuration settings weaken trust

The goal is to detect insecure or inconsistent trust states caused by misconfiguration.

# How It Works 

The tool performs four main checks:

Parses sshd_config to extract trust-relevant settings.
Reads local SSH host public keys and computes fingerprints.
Queries DNS for SSHFP records.
Checks whether DNS responses are validated via DNSSEC (AD flag).

It then applies simple rule-based logic to determine:

Secure
Warning
Insecure

# Project structure

main.py                  CLI entry point
trust_assessor.py        Core logic and rule evaluation
ssh_config_parser.py     Parses sshd_config
host_key_analyzer.py     Reads host keys and computes fingerprints
dns_sshfp_query.py       Queries DNS for SSHFP records
dnssec_validator.py      Checks DNSSEC validation status
reporter.py              Output formatting and JSON export

# Running the Tool
Basic usage:

python main.py example.com  (example is the hostname)

Optional arguments:

--resolver <IP>         Use specific DNS resolver
--ssh-config <path>     Specify sshd_config path
--host-key-dir <path>   Specify host key directory
--json <file>           Save JSON output
--verbose               Show detailed output

# Design Notes

DNSSEC validation is based on the resolver’s AD flag.
The resolver must be trusted and configured for validation.
The tool is designed for controlled lab environments.
It assumes access to the correct host public keys.

# Limitations

Does not perform full cryptographic DNSSEC validation.
Requires correct host key access (usually run on the SSH server).
Evaluated in a lab environment, not production-scale networks.
Not a vulnerability scanner.

# Status

Core functionality is implemented.
Currently in structured testing phase, validating detection accuracy across secure and insecure scenarios.