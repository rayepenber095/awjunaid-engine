#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/logger.sh"

# Check if tool exists
check_tool() {
    local tool=$1
    if ! command -v "$tool" &>/dev/null; then
        return 1
    fi
    return 0
}

# HTTP request with retry
http_request() {
    local method=$1
    local url=$2
    local max_retries=${3:-3}
    local attempt=1
    
    while [[ $attempt -le $max_retries ]]; do
        local response
        response=$(curl -s -w "\n%{http_code}" \
            -X "$method" \
            -H "User-Agent: AWJUNAID/2.0" \
            --connect-timeout 10 \
            --max-time 10 \
            "$url" 2>/dev/null || echo "ERROR:000")
        
        local http_code
        http_code=$(echo "$response" | tail -n1)
        local body
        body=$(echo "$response" | head -n-1)
        
        if [[ "$http_code" != "000" ]]; then
            echo "$body"
            return 0
        fi
        
        if [[ $attempt -lt $max_retries ]]; then
            local wait_time=$((2 ** attempt))
            log_warn "Request failed, retry $attempt/$max_retries (waiting ${wait_time}s)"
            sleep "$wait_time"
        fi
        ((attempt++))
    done
    
    return 1
}

# Validate domain
validate_domain() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        log_error "Domain cannot be empty"
        return 1
    fi
    
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        log_error "Invalid domain format: $domain"
        return 1
    fi
    
    return 0
}

# Create output directory
create_output_dir() {
    local domain=$1
    local output_dir="${HOME}/Desktop/hunt/reports/${domain}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    echo "$output_dir"
}

# URL encode
url_encode() {
    local string=$1
    echo -n "$string" | jq -sRr @uri 2>/dev/null || echo "$string"
}

# Get HTTP status code
get_http_status() {
    local url=$1
    curl -s -o /dev/null -w "%{http_code}" -m 5 "$url" 2>/dev/null
}

# Rate limiting
apply_rate_limit() {
    local rate_limit=${1:-0}
    if [[ $rate_limit -gt 0 ]]; then
        sleep "$(echo "scale=2; 1/$rate_limit" | bc)" 2>/dev/null || sleep 0.1
    fi
}
