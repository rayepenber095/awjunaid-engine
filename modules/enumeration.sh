#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

enumeration_phase() {
    local domain=$1
    local output_dir=$2
    
    log_info "========== ENUMERATION PHASE STARTED =========="
    
    local enum_file="${output_dir}/02_enumeration.txt"
    {
        echo "=== ENUMERATION REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo ""
    } > "$enum_file"
    
    # Endpoint discovery
    enum_endpoints "$domain" >> "$enum_file"
    
    # API discovery
    enum_api_endpoints "$domain" >> "$enum_file"
    
    log_success "Enumeration complete! Results in: $enum_file"
}

enum_endpoints() {
    local domain=$1
    echo "=== ENDPOINT DISCOVERY ==="
    
    local common_paths=(
        "/api/v1"
        "/api/v2"
        "/api"
        "/admin"
        "/dashboard"
        "/login"
        "/register"
        "/user"
        "/search"
        "/profile"
    )
    
    for path in "${common_paths[@]}"; do
        local url="https://$domain$path"
        local status_code
        status_code=$(get_http_status "$url")
        
        if [[ ! "$status_code" =~ ^(000|404)$ ]]; then
            echo "[$status_code] $path"
        fi
    done
    
    echo ""
}

enum_api_endpoints() {
    local domain=$1
    echo "=== API ENDPOINT DISCOVERY ==="
    
    local api_patterns=(
        "/api/v1/users"
        "/api/v1/products"
        "/api/v2/search"
        "/graphql"
        "/.well-known/openid-configuration"
    )
    
    for pattern in "${api_patterns[@]}"; do
        local url="https://$domain$pattern"
        local status_code
        status_code=$(get_http_status "$url")
        
        if [[ "$status_code" =~ ^[2-4][0-9]{2}$ ]]; then
            echo "✓ Found: $pattern (HTTP $status_code)"
        fi
    done
    
    echo ""
}
