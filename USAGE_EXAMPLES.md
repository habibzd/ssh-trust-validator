# Usage Examples

This document provides practical examples for using the SSH Trust Validator in your lab environment.

## Basic Assessment

Assess a hostname using default paths:
```bash
python main.py example.com
```

## Lab Environment Scenarios

### Scenario 1: Insecure Configuration (No SSHFP)

When SSHFP records are missing, the tool will detect TOFU reliance:

```bash
python main.py insecure-server.lab --resolver 192.168.1.100
```

Expected findings:
- **HIGH**: No SSHFP Records Found
- Trust relies on TOFU without DNS-based verification

### Scenario 2: SSHFP Without DNSSEC

When SSHFP records exist but DNSSEC is not validated:

```bash
python main.py sshfp-no-dnssec.lab --resolver 192.168.1.100
```

Expected findings:
- **INFO**: SSHFP Records Found
- **HIGH**: DNSSEC Validation Failed or Not Available
- SSHFP records can be spoofed via DNS attacks

### Scenario 3: Secure Configuration

When SSHFP records exist, DNSSEC is validated, and fingerprints match:

```bash
python main.py secure-server.lab --resolver 192.168.1.100
```

Expected findings:
- **INFO**: SSHFP Records Found
- **INFO**: DNSSEC Validation Successful
- **INFO**: SSHFP Fingerprints Match Host Keys
- Overall Status: **SECURE**

### Scenario 4: Fingerprint Mismatch

When SSHFP records don't match actual host keys:

```bash
python main.py mismatched.lab --resolver 192.168.1.100
```

Expected findings:
- **HIGH**: SSHFP Fingerprint Mismatch
- DNS-published fingerprints do not match server host keys

## Advanced Usage

### Custom SSH Configuration

If SSH config is in a non-standard location:

```bash
python main.py example.com --ssh-config /custom/path/sshd_config
```

### Custom Host Key Directory

If host keys are in a different directory:

```bash
python main.py example.com --host-key-dir /custom/path/ssh
```

### Generate JSON Report for Evaluation

Save detailed JSON output for screenshots/logs:

```bash
python main.py example.com --json assessment-report.json
```

### Verbose Output

Show detailed configuration and DNS information:

```bash
python main.py example.com --verbose
```

### Combined Options

Full assessment with all options:

```bash
python main.py secure-server.lab \
  --resolver 192.168.1.100 \
  --ssh-config /etc/ssh/sshd_config \
  --host-key-dir /etc/ssh \
  --json secure-assessment.json \
  --verbose
```

## Exit Codes

The tool uses exit codes for automation:

- `0`: No issues (secure configuration)
- `1`: Warnings present
- `2`: High severity findings (insecure)

Example script:
```bash
python main.py example.com
case $? in
  0) echo "Configuration is secure" ;;
  1) echo "Warnings detected" ;;
  2) echo "High severity issues found" ;;
esac
```

## Troubleshooting

### Permission Errors

If you get permission denied errors:

```bash
# Option 1: Run with sudo (Linux)
sudo python main.py example.com

# Option 2: Copy files to readable location
sudo cp /etc/ssh/sshd_config /tmp/
sudo cp /etc/ssh/ssh_host_*_key.pub /tmp/ssh/
python main.py example.com --ssh-config /tmp/sshd_config --host-key-dir /tmp/ssh
```

### DNS Resolution Issues

If DNS queries fail:

```bash
# Test DNS resolution first
nslookup example.com 192.168.1.100

# Then run validator
python main.py example.com --resolver 192.168.1.100
```

### DNSSEC Validation Unknown

If DNSSEC status is always unknown:

1. Verify validating resolver is configured correctly
2. Ensure DNSSEC is enabled on the resolver
3. Check that DNS zone is signed
4. Verify network connectivity to resolver

## Evaluation Workflow

For your project evaluation:

1. **Insecure Scenario**:
   ```bash
   python main.py insecure.lab --resolver 192.168.1.100 --json insecure-report.json
   ```

2. **Secure Scenario**:
   ```bash
   python main.py secure.lab --resolver 192.168.1.100 --json secure-report.json
   ```

3. **Compare Outputs**:
   - Insecure scenario should show HIGH severity findings
   - Secure scenario should show INFO findings and secure status
   - JSON reports can be used for documentation

4. **Screenshots**:
   - Run with `--verbose` for detailed output
   - Capture both insecure and secure scenarios
   - Include JSON reports in your documentation
