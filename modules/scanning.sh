#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

# Vulnerability counters
declare -A VULNS
VULNS[injection]=0
VULNS[xss]=0
VULNS[broken_auth]=0
VULNS[idor]=0
VULNS[misc]=0

scanning_phase() {
    local domain=$1
    local output_dir=$2
    local scan_mode=$3
    
    log_info "========== SCANNING PHASE STARTED =========="
    
    local scan_file="${output_dir}/03_scanning.txt"
    {
        echo "=== VULNERABILITY SCANNING REPORT ==="
        echo "Domain: $domain"
        echo "Scan Mode: $scan_mode"
        echo "Date: $(date)"
        echo ""
    } > "$scan_file"
    
    # OWASP scanning
    scan_injection "$domain" >> "$scan_file"
    scan_xss "$domain" >> "$scan_file"
    scan_broken_auth "$domain" >> "$scan_file"
    scan_idor "$domain" >> "$scan_file"
    scan_misc "$domain" >> "$scan_file"
    
    log_success "Scanning complete! Results in: $scan_file"
}

scan_injection() {
    local domain=$1
    echo "=== INJECTION VULNERABILITIES ==="
    
    local test_urls=(
        "https://$domain/search"
        "https://$domain/api/search"
    )
    
    local sqli_payloads=(
        "' OR '1'='1"
        "' OR 1=1 --"
        "admin' --"
    )
    
    echo "Testing for SQL Injection..."
    for url in "${test_urls[@]}"; do
        for payload in "${sqli_payloads[@]}"; do
            local encoded_payload
            encoded_payload=$(url_encode "$payload")
            
            local response
            response=$(curl -s -m 5 "$url?q=$encoded_payload" 2>/dev/null || true)
            
            if echo "$response" | grep -qi "sql\|mysql\|syntax error"; then
                echo "⚠️  Potential SQLi: $url"
                ((VULNS[injection]++))
            fi
        done
    done
    
    echo ""
}

scan_xss() {
    local domain=$1
    echo "=== XSS VULNERABILITIES ==="
    
    local xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror='alert(1)'>"
    )
    
    local test_params=(
        "search"
        "q"
        "name"
    )
    
    echo "Testing for XSS..."
    for param in "${test_params[@]}"; do
        for payload in "${xss_payloads[@]}"; do
            local encoded_payload
            encoded_payload=$(url_encode "$payload")
            
            local response
            response=$(curl -s -m 5 "https://$domain/?$param=$encoded_payload" 2>/dev/null)
            
            if echo "$response" | grep -q "<script>alert('XSS')</script>"; then
                echo "⚠️  Reflected XSS Found: Parameter '$param'"
                ((VULNS[xss]++))
            fi
        done
    done
    
    echo ""
}

scan_broken_auth() {
    local domain=$1
    echo "=== BROKEN AUTHENTICATION ==="
    
    local common_creds=(
        "admin:admin"
        "admin:password"
        "test:test"
    )
    
    echo "Testing default credentials..."
    for cred in "${common_creds[@]}"; do
        local user="${cred%:*}"
        local pass="${cred#*:}"
        
        local response
        response=$(curl -s -m 5 -u "$user:$pass" "https://$domain/api/auth/login" 2>/dev/null || true)
        
        if echo "$response" | grep -qi "success\|token"; then
            echo "⚠️  Weak Credentials: $user:$pass"
            ((VULNS[broken_auth]++))
        fi
    done
    
    echo ""
}

scan_idor() {
    local domain=$1
    echo "=== IDOR VULNERABILITIES ==="
    
    local idor_patterns=(
        "/api/user/1"
        "/api/user/2"
        "/api/profile/1"
    )
    
    echo "Testing for IDOR..."
    for pattern in "${idor_patterns[@]}"; do
        local url1="https://$domain$pattern"
        local url2="https://$domain${pattern%/*}/2"
        
        local resp1
        local resp2
        resp1=$(curl -s -m 5 "$url1" 2>/dev/null | md5sum | cut -d' ' -f1)
        resp2=$(curl -s -m 5 "$url2" 2>/dev/null | md5sum | cut -d' ' -f1)
        
        if [[ "$resp1" != "$resp2" ]]; then
            echo "ℹ️  Different responses: $pattern"
            ((VULNS[idor]++))
        fi
    done
    
    echo ""
}

scan_misc() {
    local domain=$1
    echo "=== MISCONFIGURATION CHECKS ==="
    
    local backup_files=(
        "/.git"
        "/.env"
        "/config.php.bak"
    )
    
    echo "Checking for exposed files..."
    for file in "${backup_files[@]}"; do
        local status
        status=$(get_http_status "https://$domain$file")
        
        if [[ "$status" == "200" ]]; then
            echo "⚠️  Exposed: $file (HTTP $status)"
            ((VULNS[misc]++))
        fi
    done
    
    echo ""
}
