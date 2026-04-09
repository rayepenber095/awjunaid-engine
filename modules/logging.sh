#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

LOGGING_VULN_COUNT=0

# --- Logging & Monitoring Main Entry ---

scan_logging() {
    local domain=$1
    echo "=== INSUFFICIENT LOGGING & MONITORING ==="
    log_info "Starting logging/monitoring checks on $domain"

    logging_security_headers "$domain"
    logging_exposed_log_files "$domain"
    logging_monitoring_endpoints "$domain"
    logging_error_verbosity "$domain"
    logging_sensitive_data_in_responses "$domain"
    logging_correlation_id "$domain"

    echo "Logging/monitoring checks completed. Potential findings: $LOGGING_VULN_COUNT"
    echo ""
}

# --- Security Header Presence Validation ---

logging_security_headers() {
    local domain=$1
    echo "--- Security Header Presence Validation ---"

    local headers
    headers=$(curl -s -I -m 10 \
        -H "User-Agent: AWJUNAID/2.0" \
        "https://$domain" 2>/dev/null \
        || curl -s -I -m 10 \
        -H "User-Agent: AWJUNAID/2.0" \
        "http://$domain" 2>/dev/null || true)

    declare -A required_headers
    required_headers["Strict-Transport-Security"]="Enforces HTTPS connections"
    required_headers["X-Content-Type-Options"]="Prevents MIME sniffing"
    required_headers["X-Frame-Options"]="Prevents clickjacking"
    required_headers["Content-Security-Policy"]="Restricts content sources"
    required_headers["X-XSS-Protection"]="Basic XSS filter (legacy)"
    required_headers["Referrer-Policy"]="Controls referrer information"
    required_headers["Permissions-Policy"]="Controls browser feature access"
    required_headers["Cache-Control"]="Controls caching behavior"

    for header in "${!required_headers[@]}"; do
        if echo "$headers" | grep -qi "^${header}:"; then
            echo "✓  $header: Present"
        else
            echo "✗  [MEDIUM] $header: Missing — ${required_headers[$header]}"
            echo "    CWE-693 | CVSS: 5.3 (Medium)"
            ((LOGGING_VULN_COUNT++))
        fi
    done
    echo ""
}

# --- Exposed Log File Scanning ---

logging_exposed_log_files() {
    local domain=$1
    echo "--- Exposed Log File Scanning ---"

    local log_paths=(
        "/logs"
        "/log"
        "/debug.log"
        "/error.log"
        "/access.log"
        "/application.log"
        "/app.log"
        "/server.log"
        "/logs/debug.log"
        "/logs/error.log"
        "/logs/access.log"
        "/logs/app.log"
        "/.htaccess"
        "/var/log/nginx/access.log"
        "/var/log/apache2/access.log"
        "/tmp/app.log"
        "/storage/logs/laravel.log"
        "/wp-content/debug.log"
    )

    for path in "${log_paths[@]}"; do
        local url="https://$domain$path"
        local status
        status=$(get_http_status "$url")

        if [[ "$status" == "200" ]]; then
            echo "⚠️  [HIGH] Exposed log file: $path (HTTP $status)"
            echo "    URL: $url"
            echo "    CWE-532 | CVSS: 7.5 (High)"
            echo "    Remediation: Restrict access to log directories via web server config"

            # Sample first 3 lines to check for sensitive data
            local sample
            sample=$(curl -s -m 10 "$url" 2>/dev/null | head -3 || true)
            if echo "$sample" | grep -qiE "password|token|secret|api.key|bearer|auth"; then
                echo "    ⚠️  [CRITICAL] Sensitive data found in log file!"
                echo "       CWE-312 | CVSS: 9.1 (Critical)"
            fi
            ((LOGGING_VULN_COUNT++))
        fi
    done
    echo ""
}

# --- Monitoring / Alerting Capability Detection ---

logging_monitoring_endpoints() {
    local domain=$1
    echo "--- Monitoring / Alerting Capability Detection ---"

    local monitoring_paths=(
        "/health"
        "/healthz"
        "/health/live"
        "/health/ready"
        "/metrics"
        "/prometheus"
        "/actuator"
        "/actuator/health"
        "/actuator/metrics"
        "/actuator/env"
        "/actuator/beans"
        "/actuator/mappings"
        "/_cat/indices"
        "/_cluster/health"
        "/status"
        "/ping"
    )

    local found_monitoring=0

    for path in "${monitoring_paths[@]}"; do
        local url="https://$domain$path"
        local status
        status=$(get_http_status "$url")

        if [[ "$status" == "200" ]]; then
            echo "ℹ️  Monitoring endpoint found: $path (HTTP $status)"

            # Check if actuator exposes sensitive data
            if echo "$path" | grep -qE "actuator/(env|beans|mappings|heapdump|threaddump|trace)"; then
                echo "⚠️  [CRITICAL] Spring Actuator sensitive endpoint exposed: $path"
                echo "    CWE-200 | CVSS: 9.8 (Critical)"
                echo "    Remediation: Restrict actuator endpoints; disable sensitive endpoints"
                ((LOGGING_VULN_COUNT++))
            fi
            found_monitoring=1
        fi
    done

    if [[ $found_monitoring -eq 0 ]]; then
        echo "ℹ️  [LOW] No monitoring endpoints detected — consider adding /health for observability"
    fi
    echo ""
}

# --- Error Message Verbosity Analysis ---

logging_error_verbosity() {
    local domain=$1
    echo "--- Error Message Verbosity Analysis ---"

    local error_trigger_paths=(
        "/api/v1/user/undefined"
        "/api/v1/../../../etc/passwd"
        "/api/v1/%00"
        "/api/v1/user?id='"
        "/api/v1/search?q=<script>"
        "/'\";<>&"
    )

    for path in "${error_trigger_paths[@]}"; do
        local url="https://$domain$path"
        local response
        response=$(curl -s -m 10 "$url" \
            -H "User-Agent: AWJUNAID/2.0" 2>/dev/null || true)

        # Check for stack traces / internal paths
        if echo "$response" | grep -qiE "at .*\.(java|js|py|rb|php):[0-9]+|Traceback \(most recent|Fatal error:|stack trace:|Exception in thread|com\.[a-z]+\.[a-z]+\." ; then
            echo "⚠️  [MEDIUM] Verbose error / stack trace leaked at: $path"
            echo "    CWE-209 | CVSS: 5.3 (Medium)"
            echo "    Remediation: Configure production error handling to suppress stack traces"
            ((LOGGING_VULN_COUNT++))
        fi

        # Check for internal IP disclosure
        if echo "$response" | grep -qE "10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+"; then
            echo "⚠️  [MEDIUM] Internal IP disclosed in error response at: $path"
            echo "    CWE-209 | CVSS: 4.3 (Medium)"
            ((LOGGING_VULN_COUNT++))
        fi
    done
    echo ""
}

# --- Sensitive Data in Responses Detection ---

logging_sensitive_data_in_responses() {
    local domain=$1
    echo "--- Sensitive Data in Responses Detection ---"

    local endpoints=(
        "https://$domain/api/v1/user"
        "https://$domain/api/v1/users"
        "https://$domain/api/v1/profile"
        "https://$domain/api/config"
        "https://$domain/api/v1/settings"
    )

    # Patterns: credit cards, SSN, passwords, tokens, keys
    local sensitive_patterns=(
        "[0-9]{4}[[:space:]-]?[0-9]{4}[[:space:]-]?[0-9]{4}[[:space:]-]?[0-9]{4}"  # Credit card
        "[0-9]{3}-[0-9]{2}-[0-9]{4}"                                                  # SSN
        '"password"\s*:\s*"[^"]+'                                                      # password field
        '"token"\s*:\s*"[^"]+'                                                         # token field
        '"api_key"\s*:\s*"[^"]+'                                                       # api_key
        '"secret"\s*:\s*"[^"]+'                                                        # secret
        'Bearer [A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'                  # JWT
        'AWS_ACCESS_KEY_ID|AKIA[A-Z0-9]{16}'                                          # AWS key
    )

    for url in "${endpoints[@]}"; do
        local response
        response=$(curl -s -m 10 "$url" \
            -H "User-Agent: AWJUNAID/2.0" 2>/dev/null || true)

        if [[ -n "$response" ]]; then
            for pattern in "${sensitive_patterns[@]}"; do
                if echo "$response" | grep -qE "$pattern"; then
                    echo "⚠️  [CRITICAL] Sensitive data pattern found in response: $url"
                    echo "    Pattern: $pattern"
                    echo "    CWE-312 | CVSS: 9.1 (Critical)"
                    echo "    Remediation: Mask/redact sensitive fields; apply data minimization"
                    ((LOGGING_VULN_COUNT++))
                    break
                fi
            done
        fi
    done
    echo ""
}

# --- Request Correlation ID Checking ---

logging_correlation_id() {
    local domain=$1
    echo "--- Request Correlation ID Checking ---"

    local headers
    headers=$(curl -s -I -m 10 \
        -H "User-Agent: AWJUNAID/2.0" \
        "https://$domain" 2>/dev/null || true)

    local correlation_headers=(
        "X-Request-ID"
        "X-Correlation-ID"
        "X-Trace-ID"
        "X-B3-TraceId"
        "Request-Id"
        "traceparent"
    )

    local found=0
    for header in "${correlation_headers[@]}"; do
        if echo "$headers" | grep -qi "^${header}:"; then
            echo "✓  Correlation header present: $header"
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        echo "ℹ️  [LOW] No request correlation ID headers detected"
        echo "    Recommendation: Add X-Request-ID or X-Correlation-ID for distributed tracing"
        echo "    CWE-778 | CVSS: 2.6 (Low)"
    fi
    echo ""
}
