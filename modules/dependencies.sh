#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

DEPS_VULN_COUNT=0

# --- Known Vulnerabilities Main Entry ---

scan_dependencies() {
    local domain=$1
    echo "=== USING COMPONENTS WITH KNOWN VULNERABILITIES ==="
    log_info "Starting dependency/component scanning on $domain"

    deps_version_from_headers "$domain"
    deps_package_file_discovery "$domain"
    deps_outdated_server_software "$domain"
    deps_ssl_tls_check "$domain"
    deps_docker_socket "$domain"

    echo "Dependency checks completed. Potential findings: $DEPS_VULN_COUNT"
    echo ""
}

# --- Version Detection from Headers ---

deps_version_from_headers() {
    local domain=$1
    echo "--- Dependency Version Detection from Headers ---"

    local headers
    headers=$(curl -s -I -m 10 \
        -H "User-Agent: AWJUNAID/2.0" \
        "https://$domain" 2>/dev/null \
        || curl -s -I -m 10 \
        -H "User-Agent: AWJUNAID/2.0" \
        "http://$domain" 2>/dev/null || true)

    local version_headers=(
        "Server"
        "X-Powered-By"
        "X-AspNet-Version"
        "X-AspNetMvc-Version"
        "X-Generator"
        "X-Drupal-Cache"
        "Via"
    )

    for header in "${version_headers[@]}"; do
        local value
        value=$(echo "$headers" | grep -i "^${header}:" | head -1 | cut -d':' -f2- | xargs 2>/dev/null || true)
        if [[ -n "$value" ]]; then
            echo "ℹ️  Header '$header': $value"

            if echo "$value" | grep -qiE "apache/2\.[01]\.|nginx/1\.[0-9]\.[0-9]+\b|php/[45]\.|openssl/1\.0\.[01]"; then
                echo "⚠️  [HIGH] Outdated/vulnerable version in '$header': $value"
                echo "    CWE-1104 | CVSS: 7.5 (High)"
                echo "    Remediation: Update to the latest stable version"
                ((DEPS_VULN_COUNT++))
            fi
        fi
    done
    echo ""
}

# --- Package File Discovery ---

deps_package_file_discovery() {
    local domain=$1
    echo "--- Package File Discovery ---"

    local package_files=(
        "/package.json"
        "/package-lock.json"
        "/composer.json"
        "/composer.lock"
        "/requirements.txt"
        "/Gemfile"
        "/Gemfile.lock"
        "/pom.xml"
        "/go.mod"
        "/go.sum"
        "/yarn.lock"
        "/Pipfile"
        "/Pipfile.lock"
        "/.npmrc"
        "/bower.json"
        "/build.gradle"
        "/setup.py"
    )

    for file in "${package_files[@]}"; do
        local url="https://$domain$file"
        local status
        status=$(get_http_status "$url")

        if [[ "$status" == "200" ]]; then
            echo "⚠️  [MEDIUM] Exposed package file: $file (HTTP $status)"
            echo "    URL: $url"
            echo "    CWE-538 | CVSS: 5.3 (Medium)"
            echo "    Remediation: Block access to dependency files via web server config"

            local content
            content=$(curl -s -m 10 "$url" 2>/dev/null | head -50 || true)
            if [[ -n "$content" ]]; then
                echo "    Preview (first 5 lines):"
                echo "$content" | head -5 | sed 's/^/      /'
                _check_known_vuln_packages "$content"
            fi
            ((DEPS_VULN_COUNT++))
        fi
    done
    echo ""
}

# Internal: match package content against known-vulnerable patterns
_check_known_vuln_packages() {
    local content=$1

    local vuln_patterns=(
        '"lodash".*"[34]\.'
        '"jquery".*"[12]\.'
        '"express".*"[34]\.'
        '"node-serialize".*"0\.'
        '"handlebars".*"[234]\.'
        '"axios".*"0\.0[0-9]\.'
        '"serialize-javascript".*"[12]\.'
    )

    for pattern in "${vuln_patterns[@]}"; do
        if echo "$content" | grep -qE "$pattern"; then
            echo "    ⚠️  Potentially vulnerable package version detected (pattern: $pattern)"
            echo "       CWE-1104 | CVSS: 7.5 (High) - verify exact version against CVE database"
        fi
    done
}

# --- Outdated Server Software Detection ---

deps_outdated_server_software() {
    local domain=$1
    echo "--- Outdated Server Software Detection ---"

    local headers
    headers=$(curl -s -I -m 10 \
        -H "User-Agent: AWJUNAID/2.0" \
        "https://$domain" 2>/dev/null \
        || curl -s -I -m 10 \
        -H "User-Agent: AWJUNAID/2.0" \
        "http://$domain" 2>/dev/null || true)

    local server
    server=$(echo "$headers" | grep -i "^Server:" | head -1 | cut -d':' -f2- | xargs 2>/dev/null || true)

    if [[ -n "$server" ]]; then
        echo "Server: $server"

        # Tomcat EOL versions
        if echo "$server" | grep -qiE "Tomcat/[1-8]\.[0-4]\."; then
            echo "⚠️  [HIGH] Outdated Apache Tomcat version: $server"
            echo "    CWE-1104 | CVSS: 8.1 (High)"
            ((DEPS_VULN_COUNT++))
        fi

        # IIS old versions
        if echo "$server" | grep -qiE "IIS/[1-6]\."; then
            echo "⚠️  [HIGH] Outdated IIS version: $server"
            echo "    CWE-1104 | CVSS: 8.1 (High)"
            ((DEPS_VULN_COUNT++))
        fi

        # WordPress fingerprint
        if echo "$headers" | grep -qi "WordPress"; then
            echo "ℹ️  WordPress detected — check /wp-includes/version.php for version"
        fi
    else
        echo "✓  Server header suppressed (good practice)"
    fi
    echo ""
}

# --- SSL/TLS Version and Cipher Vulnerability Check ---

deps_ssl_tls_check() {
    local domain=$1
    echo "--- SSL/TLS Version and Cipher Vulnerability Check ---"

    if ! check_tool openssl; then
        echo "ℹ️  openssl not available; skipping SSL/TLS checks"
        echo ""
        return 0
    fi

    # Test for SSLv3 (POODLE)
    local ssl3_result
    ssl3_result=$(echo "" | openssl s_client -connect "${domain}:443" \
        -ssl3 2>&1 | grep -i "ssl" || true)
    if echo "$ssl3_result" | grep -qi "handshake\|connected"; then
        echo "⚠️  [CRITICAL] SSLv3 supported (POODLE vulnerability)"
        echo "    CVE-2014-3566 | CVSS: 3.4"
        ((DEPS_VULN_COUNT++))
    else
        echo "✓  SSLv3 not supported"
    fi

    # Test for TLS 1.0
    local tls10_result
    tls10_result=$(echo "" | openssl s_client -connect "${domain}:443" \
        -tls1 2>&1 | grep -i "handshake\|connected" || true)
    if [[ -n "$tls10_result" ]]; then
        echo "⚠️  [MEDIUM] TLS 1.0 supported (BEAST/POODLE vectors)"
        echo "    CWE-326 | CVSS: 5.9 (Medium)"
        echo "    Remediation: Disable TLS 1.0 and 1.1; enforce TLS 1.2+"
        ((DEPS_VULN_COUNT++))
    else
        echo "✓  TLS 1.0 not supported"
    fi

    # Check certificate expiry
    local cert_expiry
    cert_expiry=$(echo "" | openssl s_client -connect "${domain}:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d'=' -f2 || true)
    if [[ -n "$cert_expiry" ]]; then
        echo "ℹ️  Certificate expiry: $cert_expiry"
        local expiry_epoch
        expiry_epoch=$(date -d "$cert_expiry" +%s 2>/dev/null \
            || date -j -f "%b %d %H:%M:%S %Y %Z" "$cert_expiry" +%s 2>/dev/null \
            || true)
        if [[ -z "$expiry_epoch" ]]; then
            log_debug "Could not parse certificate expiry date: $cert_expiry"
        else
            local now_epoch
            now_epoch=$(date +%s)
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            if [[ $days_left -lt 30 ]]; then
                echo "⚠️  [MEDIUM] Certificate expires in $days_left days"
                ((DEPS_VULN_COUNT++))
            fi
        fi
    fi
    echo ""
}

# --- Docker Socket Exposure Scanning ---

deps_docker_socket() {
    local domain=$1
    echo "--- Docker Socket Exposure Scanning ---"

    local docker_endpoints=(
        "https://$domain:2375/version"
        "http://$domain:2375/version"
        "https://$domain:2376/version"
        "http://$domain:2376/version"
        "https://$domain/v1.41/version"
        "https://$domain/_ping"
    )

    for url in "${docker_endpoints[@]}"; do
        local response
        response=$(curl -s -m 5 "$url" \
            -H "User-Agent: AWJUNAID/2.0" 2>/dev/null || true)

        if echo "$response" | grep -qiE '"ApiVersion"|"DockerRootDir"|"Version":.*"[0-9]'; then
            echo "⚠️  [CRITICAL] Docker API exposed: $url"
            echo "    CWE-284 | CVSS: 10.0 (Critical)"
            echo "    Remediation: Restrict Docker socket to localhost; use TLS authentication"
            ((DEPS_VULN_COUNT++))
        fi
    done

    echo "Docker socket scan complete."
    echo ""
}
