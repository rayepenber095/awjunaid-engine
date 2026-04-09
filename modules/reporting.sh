#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"

reporting_phase() {
    local domain=$1
    local output_dir=$2
    local start_time=$3

    log_info "========== REPORTING PHASE STARTED =========="

    generate_json_report "$domain" "$output_dir" "$start_time"
    generate_txt_report "$domain" "$output_dir" "$start_time"
    generate_markdown_report "$domain" "$output_dir" "$start_time"
    generate_html_report "$domain" "$output_dir" "$start_time"

    log_success "All reports generated in: $output_dir"
}

# --- Collect all findings from scan output ---
_collect_findings() {
    local output_dir=$1
    local scan_file="${output_dir}/03_scanning.txt"
    local findings_file="${output_dir}/_findings_cache.txt"

    if [[ ! -f "$scan_file" ]]; then
        echo "" > "$findings_file"
        return
    fi

    grep -E "^⚠️|^\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]|\[LOW\]" "$scan_file" \
        > "$findings_file" 2>/dev/null || true
}

_count_severity() {
    local output_dir=$1
    local severity=$2
    local findings_file="${output_dir}/_findings_cache.txt"
    grep -c "\[$severity\]" "$findings_file" 2>/dev/null || echo 0
}

_total_findings() {
    local output_dir=$1
    local findings_file="${output_dir}/_findings_cache.txt"
    wc -l < "$findings_file" 2>/dev/null || echo 0
}

# --- JSON Report ---

generate_json_report() {
    local domain=$1
    local output_dir=$2
    local start_time=$3
    local json_file="${output_dir}/REPORT.json"

    _collect_findings "$output_dir"

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    local critical_count high_count medium_count low_count total_count
    critical_count=$(_count_severity "$output_dir" "CRITICAL")
    high_count=$(_count_severity "$output_dir" "HIGH")
    medium_count=$(_count_severity "$output_dir" "MEDIUM")
    low_count=$(_count_severity "$output_dir" "LOW")
    total_count=$(( critical_count + high_count + medium_count + low_count ))

    cat > "$json_file" << JSONEOF
{
  "scan_metadata": {
    "domain": "$domain",
    "scan_date": "$(date -Iseconds)",
    "total_duration_seconds": $duration,
    "scan_status": "completed",
    "engine_version": "2.0"
  },
  "vulnerability_summary": {
    "total_vulnerabilities": $total_count,
    "critical": $critical_count,
    "high": $high_count,
    "medium": $medium_count,
    "low": $low_count
  },
  "severity_classification": {
    "CRITICAL": {"cvss_range": "9.0-10.0", "response_time": "Immediate (24h)"},
    "HIGH":     {"cvss_range": "7.0-8.9",  "response_time": "Short-term (7 days)"},
    "MEDIUM":   {"cvss_range": "4.0-6.9",  "response_time": "Medium-term (30 days)"},
    "LOW":      {"cvss_range": "0.1-3.9",  "response_time": "Long-term (90 days)"}
  },
  "owasp_coverage": [
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery"
  ],
  "status": "success"
}
JSONEOF

    log_success "JSON report: $json_file"
}

# --- Plain Text Report ---

generate_txt_report() {
    local domain=$1
    local output_dir=$2
    local start_time=$3
    local txt_file="${output_dir}/REPORT.txt"

    _collect_findings "$output_dir"

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    local critical_count high_count medium_count low_count total_count
    critical_count=$(_count_severity "$output_dir" "CRITICAL")
    high_count=$(_count_severity "$output_dir" "HIGH")
    medium_count=$(_count_severity "$output_dir" "MEDIUM")
    low_count=$(_count_severity "$output_dir" "LOW")
    total_count=$(( critical_count + high_count + medium_count + low_count ))

    cat > "$txt_file" << TXTEOF
================================================================================
                    AWJUNAID SCRIPT ENGINE - SECURITY REPORT
================================================================================

EXECUTIVE SUMMARY
================================================================================
Domain:                     $domain
Scan Date:                  $(date)
Total Scan Duration:        ${duration}s
Report Generated:           $(date '+%Y-%m-%d %H:%M:%S')
Engine Version:             2.0

VULNERABILITY SUMMARY
================================================================================
Total Findings:             $total_count
  Critical (CVSS 9.0-10.0): $critical_count
  High     (CVSS 7.0-8.9):  $high_count
  Medium   (CVSS 4.0-6.9):  $medium_count
  Low      (CVSS 0.1-3.9):  $low_count

SEVERITY CLASSIFICATION & REMEDIATION SLA
================================================================================
CRITICAL — Immediate action required (within 24 hours)
  - Remote code execution, authentication bypass, credential exposure
HIGH     — Short-term remediation (within 7 days)
  - Significant data exposure, privilege escalation, SSRF
MEDIUM   — Medium-term remediation (within 30 days)
  - Information disclosure, misconfiguration, weak TLS
LOW      — Long-term remediation (within 90 days)
  - Missing headers, verbose errors, minor information leaks

OWASP TOP 10 (2021) COVERAGE
================================================================================
A01: Broken Access Control       — IDOR, path traversal, mass assignment
A02: Cryptographic Failures      — SSL/TLS versions, weak ciphers, cert expiry
A03: Injection                   — SQL, XSS, XXE, command injection
A04: Insecure Design             — Business logic flaws
A05: Security Misconfiguration   — Exposed files, CORS, Docker socket
A06: Vulnerable Components       — Outdated libraries, known CVEs
A07: Authentication Failures     — Default creds, JWT flaws, rate limiting
A08: Data Integrity Failures     — Deserialization, prototype pollution
A09: Logging & Monitoring        — Missing headers, exposed logs, error verbosity
A10: SSRF                        — Cloud metadata, localhost, internal services

================================================================================
Report Generated by: AWJUNAID Script Engine v2.0
CWE References: https://cwe.mitre.org/
CVSS Calculator: https://www.first.org/cvss/calculator/3.1
OWASP Top 10: https://owasp.org/www-project-top-ten/
================================================================================
TXTEOF

    log_success "TXT report: $txt_file"
}

# --- Markdown Report ---

generate_markdown_report() {
    local domain=$1
    local output_dir=$2
    local start_time=$3
    local md_file="${output_dir}/REPORT.md"

    _collect_findings "$output_dir"

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    local critical_count high_count medium_count low_count total_count
    critical_count=$(_count_severity "$output_dir" "CRITICAL")
    high_count=$(_count_severity "$output_dir" "HIGH")
    medium_count=$(_count_severity "$output_dir" "MEDIUM")
    low_count=$(_count_severity "$output_dir" "LOW")
    total_count=$(( critical_count + high_count + medium_count + low_count ))

    cat > "$md_file" << MDEOF
# AWJUNAID Script Engine — Security Report

## Executive Summary

| Field | Value |
|-------|-------|
| **Target Domain** | \`$domain\` |
| **Scan Date** | $(date) |
| **Duration** | ${duration}s |
| **Engine Version** | 2.0 |

## Vulnerability Summary

| Severity | Count | CVSS Range | Response SLA |
|----------|-------|------------|--------------|
| 🔴 **Critical** | $critical_count | 9.0–10.0 | 24 hours |
| 🟠 **High** | $high_count | 7.0–8.9 | 7 days |
| 🟡 **Medium** | $medium_count | 4.0–6.9 | 30 days |
| 🟢 **Low** | $low_count | 0.1–3.9 | 90 days |
| **Total** | **$total_count** | | |

## OWASP Top 10 (2021) Coverage

| ID | Category | Checks Performed |
|----|----------|-----------------|
| A01 | Broken Access Control | IDOR, path traversal (LFI/RFI), mass assignment |
| A02 | Cryptographic Failures | SSL/TLS versions, weak ciphers, certificate expiry |
| A03 | Injection | SQL injection, XSS, XXE, command injection |
| A04 | Insecure Design | Business logic flaws (negative prices, workflow bypass) |
| A05 | Security Misconfiguration | CORS, exposed files, Docker socket, verbose errors |
| A06 | Vulnerable & Outdated Components | Header version detection, package file exposure, CVE matching |
| A07 | Identification & Authentication Failures | Default credentials, JWT flaws, rate limiting |
| A08 | Software & Data Integrity Failures | Deserialization (Java/Python/PHP/Node), prototype pollution |
| A09 | Security Logging & Monitoring Failures | Missing security headers, exposed logs, error verbosity |
| A10 | Server-Side Request Forgery (SSRF) | Cloud metadata, localhost, URL parameter probing |

## Remediation Recommendations

### Critical Findings
- Immediately patch or mitigate all critical vulnerabilities
- Rotate any exposed credentials, tokens, or API keys
- Engage incident response team if exploitation is suspected

### High Findings
- Schedule remediation within 7 days
- Apply temporary mitigations (WAF rules) where possible

### General Best Practices
- Keep all dependencies up to date
- Implement a Content Security Policy (CSP)
- Enable structured logging with correlation IDs
- Conduct regular penetration testing

## References

- [CWE Database](https://cwe.mitre.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [NVD CVE Database](https://nvd.nist.gov/)

---
*Report generated by AWJUNAID Script Engine v2.0*
MDEOF

    log_success "Markdown report: $md_file"
}

# --- HTML Dashboard Report ---

generate_html_report() {
    local domain=$1
    local output_dir=$2
    local start_time=$3
    local html_file="${output_dir}/REPORT.html"

    _collect_findings "$output_dir"

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    local critical_count high_count medium_count low_count total_count
    critical_count=$(_count_severity "$output_dir" "CRITICAL")
    high_count=$(_count_severity "$output_dir" "HIGH")
    medium_count=$(_count_severity "$output_dir" "MEDIUM")
    low_count=$(_count_severity "$output_dir" "LOW")
    total_count=$(( critical_count + high_count + medium_count + low_count ))

    local scan_date
    scan_date=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$html_file" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AWJUNAID Security Report — ${domain}</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
    h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
    h2 { color: #79c0ff; margin-top: 30px; }
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }
    .meta-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
    .meta-card .label { font-size: 0.8em; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
    .meta-card .value { font-size: 1.2em; font-weight: bold; margin-top: 4px; }
    .severity-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }
    .sev-card { border-radius: 8px; padding: 20px; text-align: center; }
    .sev-critical { background: #2d0000; border: 1px solid #f85149; }
    .sev-high     { background: #2d1400; border: 1px solid #d29922; }
    .sev-medium   { background: #2d2000; border: 1px solid #e3b341; }
    .sev-low      { background: #0d2a0d; border: 1px solid #3fb950; }
    .sev-card .count { font-size: 2.5em; font-weight: bold; }
    .sev-critical .count { color: #f85149; }
    .sev-high     .count { color: #d29922; }
    .sev-medium   .count { color: #e3b341; }
    .sev-low      .count { color: #3fb950; }
    .sev-card .label { font-size: 0.9em; color: #8b949e; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; margin: 16px 0; }
    th { background: #21262d; padding: 12px 16px; text-align: left; color: #8b949e; font-size: 0.85em; text-transform: uppercase; }
    td { padding: 12px 16px; border-top: 1px solid #21262d; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: bold; }
    .badge-critical { background: #3d0000; color: #f85149; }
    .badge-high     { background: #3d2000; color: #d29922; }
    .badge-medium   { background: #3d3000; color: #e3b341; }
    .badge-low      { background: #1a3a1a; color: #3fb950; }
    footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; font-size: 0.85em; color: #8b949e; text-align: center; }
    a { color: #58a6ff; }
  </style>
</head>
<body>
  <h1>🛡️ AWJUNAID Script Engine — Security Report</h1>

  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Target Domain</div>
      <div class="value">${domain}</div>
    </div>
    <div class="meta-card">
      <div class="label">Scan Date</div>
      <div class="value">${scan_date}</div>
    </div>
    <div class="meta-card">
      <div class="label">Duration</div>
      <div class="value">${duration}s</div>
    </div>
    <div class="meta-card">
      <div class="label">Engine Version</div>
      <div class="value">2.0</div>
    </div>
  </div>

  <h2>Vulnerability Summary</h2>
  <div class="severity-grid">
    <div class="sev-card sev-critical">
      <div class="count">${critical_count}</div>
      <div class="label">Critical</div>
    </div>
    <div class="sev-card sev-high">
      <div class="count">${high_count}</div>
      <div class="label">High</div>
    </div>
    <div class="sev-card sev-medium">
      <div class="count">${medium_count}</div>
      <div class="label">Medium</div>
    </div>
    <div class="sev-card sev-low">
      <div class="count">${low_count}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <h2>OWASP Top 10 (2021) Coverage</h2>
  <table>
    <thead>
      <tr><th>ID</th><th>Category</th><th>Checks Performed</th></tr>
    </thead>
    <tbody>
      <tr><td>A01</td><td>Broken Access Control</td><td>IDOR, path traversal, mass assignment</td></tr>
      <tr><td>A02</td><td>Cryptographic Failures</td><td>SSL/TLS versions, weak ciphers, certificate expiry</td></tr>
      <tr><td>A03</td><td>Injection</td><td>SQL injection, XSS, XXE, command injection</td></tr>
      <tr><td>A04</td><td>Insecure Design</td><td>Business logic flaws</td></tr>
      <tr><td>A05</td><td>Security Misconfiguration</td><td>CORS, exposed files, Docker socket, verbose errors</td></tr>
      <tr><td>A06</td><td>Vulnerable &amp; Outdated Components</td><td>Header version detection, package file exposure</td></tr>
      <tr><td>A07</td><td>Authentication Failures</td><td>Default credentials, JWT flaws, rate limiting bypass</td></tr>
      <tr><td>A08</td><td>Data Integrity Failures</td><td>Java/Python/PHP/Node deserialization, prototype pollution</td></tr>
      <tr><td>A09</td><td>Logging &amp; Monitoring Failures</td><td>Missing headers, exposed logs, error verbosity</td></tr>
      <tr><td>A10</td><td>Server-Side Request Forgery</td><td>Cloud metadata, localhost, URL parameter probing</td></tr>
    </tbody>
  </table>

  <h2>Severity Classification &amp; SLA</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>CVSS Range</th><th>Response SLA</th><th>Example Findings</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><span class="badge badge-critical">CRITICAL</span></td>
        <td>9.0–10.0</td><td>Immediate (24h)</td>
        <td>RCE, auth bypass, credential exposure, XXE file disclosure</td>
      </tr>
      <tr>
        <td><span class="badge badge-high">HIGH</span></td>
        <td>7.0–8.9</td><td>Short-term (7 days)</td>
        <td>SSRF, SQL injection, insecure deserialization</td>
      </tr>
      <tr>
        <td><span class="badge badge-medium">MEDIUM</span></td>
        <td>4.0–6.9</td><td>Medium-term (30 days)</td>
        <td>Information disclosure, CORS wildcard, TLS 1.0</td>
      </tr>
      <tr>
        <td><span class="badge badge-low">LOW</span></td>
        <td>0.1–3.9</td><td>Long-term (90 days)</td>
        <td>Missing security headers, verbose error messages</td>
      </tr>
    </tbody>
  </table>

  <h2>References</h2>
  <ul>
    <li><a href="https://cwe.mitre.org/" target="_blank">CWE Database</a></li>
    <li><a href="https://www.first.org/cvss/calculator/3.1" target="_blank">CVSS v3.1 Calculator</a></li>
    <li><a href="https://owasp.org/www-project-top-ten/" target="_blank">OWASP Top 10 2021</a></li>
    <li><a href="https://nvd.nist.gov/" target="_blank">NVD CVE Database</a></li>
  </ul>

  <footer>
    Report generated by <strong>AWJUNAID Script Engine v2.0</strong> | ${scan_date}
  </footer>
</body>
</html>
HTMLEOF

    log_success "HTML report: $html_file"
}
