# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Install dependencies:
```
pip install -r requirements.txt
```

Run the tool:
```
python main.py <hostname>
python main.py <hostname> --resolver <IP> --ssh-config <path> --host-key-dir <path> --json output.json --verbose
```

There is no test suite or linter configured in this project.

## Architecture

This is a single-pass CLI tool that assesses SSH trust configuration for a given hostname. The flow is linear:

1. `main.py` — CLI entry point. Parses args, instantiates `TrustAssessor` and `Reporter`, calls `assess_host()`, prints results, and exits with a code reflecting severity (0=clean, 1=warnings, 2=high severity).

2. `trust_assessor.py` (`TrustAssessor`) — Orchestrates all checks. `assess_host()` runs four sub-checks in sequence, accumulates `findings` dicts (each with `severity`, `title`, `description`, `reason`, optional `remediation`), and returns a single assessment dict. DNSSEC is only checked when SSHFP records are present.

3. `ssh_config_parser.py` (`SSHConfigParser`) — Parses `sshd_config` including `Include` directives (processed inline, matching OpenSSH behavior). Last-value-wins semantics. Extracts a fixed set of trust-relevant directives defined in `TRUST_RELEVANT_DIRECTIVES`.

4. `host_key_analyzer.py` (`HostKeyAnalyzer`) — Discovers `ssh_host_*_key.pub` files, decodes them, and computes SHA-256 fingerprints. Generates SSHFP-compatible records for comparison. SHA-1 fingerprint matching is not implemented.

5. `dns_sshfp_query.py` (`SSHFPQuery`) — Uses `dnspython` to query SSHFP records. Does not validate DNS response authenticity (that is handled separately).

6. `dnssec_validator.py` (`DNSSECValidator`) — Checks the AD (Authenticated Data) flag in DNS responses to determine if a validating resolver confirmed DNSSEC. Makes a direct UDP query with the DO flag set; requires a resolver IP to be reachable.

7. `reporter.py` (`Reporter`) — Formats and prints the assessment dict. Supports ANSI colors and JSON export.

## Key design constraints

- DNSSEC validation relies on the resolver's AD flag, not cryptographic verification. The resolver must be a trusted validating resolver.
- The tool is intended to run on the SSH server itself (needs access to `/etc/ssh/` for host keys and `sshd_config`).
- `DNSSECValidator.check_dnssec_validation()` requires a reachable resolver IP; if none is configured via `--resolver`, it falls back to the system resolver's first nameserver.
- All ECDSA key types (`nistp256`, `nistp384`, `nistp521`) map to SSHFP algorithm number 3 per RFC 4255.
