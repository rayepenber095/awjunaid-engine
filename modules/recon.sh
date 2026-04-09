#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/../lib/logger.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/utils.sh"

# Main reconnaissance function
recon_phase() {
    local domain=$1
    local output_dir=$2
    
    log_info "========== RECON PHASE STARTED =========="
    log_info "Target: $domain | Subdomains enumeration..."
    
    local recon_file="${output_dir}/01_recon.txt"
    {
        echo "=== RECONNAISSANCE REPORT ==="
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo ""
    } > "$recon_file"
    
    # Subdomain enumeration
    recon_subdomains "$domain" >> "$recon_file"
    
    # DNS records
    recon_dns "$domain" >> "$recon_file"
    
    # Live hosts
    recon_live_hosts "$domain" >> "$recon_file"
    
    # Reverse proxy
    recon_reverse_proxy "$domain" >> "$recon_file"
    
    # Technology detection
    recon_technology "$domain" >> "$recon_file"
    
    # Sitemap
    recon_sitemap "$domain" >> "$recon_file"
    
    # Headers
    recon_headers "$domain" >> "$recon_file"
    
    log_success "Reconnaissance complete! Results in: $recon_file"
}

recon_subdomains() {
    local domain=$1
    echo "=== SUBDOMAINS ==="
    
    if check_tool subfinder; then
        subfinder -d "$domain" -silent 2>/dev/null || true
    fi
    
    # Using crt.sh
    curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null | \
        grep -o '"name_value":"[^"]*"' | cut -d'"' -f4 | sort -u || true
    
    echo ""
}

recon_dns() {
    local domain=$1
    echo "=== DNS RECORDS ==="
    
    echo "A Records:"
    dig +short A "$domain" 2>/dev/null || echo "N/A"
    
    echo -e "\nMX Records:"
    dig +short MX "$domain" 2>/dev/null || echo "N/A"
    
    echo -e "\nNS Records:"
    dig +short NS "$domain" 2>/dev/null || echo "N/A"
    
    echo -e "\nTXT Records:"
    dig +short TXT "$domain" 2>/dev/null || echo "N/A"
    
    echo ""
}

recon_live_hosts() {
    local domain=$1
    echo "=== LIVE HOST DETECTION ==="
    
    local ip
    ip=$(dig +short "$domain" A | head -1)
    
    if [[ -n "$ip" ]]; then
        echo "Primary IP: $ip"
        
        if ping -c 1 -W 1 "$domain" &>/dev/null; then
            echo "Status: LIVE (ICMP reachable)"
        else
            local http_status
            http_status=$(get_http_status "https://$domain")
            if [[ "$http_status" =~ ^[2-4][0-9]{2}$ ]]; then
                echo "Status: LIVE (HTTP $http_status)"
            else
                echo "Status: POSSIBLY UP (DNS resolves)"
            fi
        fi
    else
        echo "Status: OFFLINE (DNS not resolving)"
    fi
    
    echo ""
}

recon_reverse_proxy() {
    local domain=$1
    echo "=== REVERSE PROXY DETECTION ==="
    
    local headers
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)
    
    if echo "$headers" | grep -qi "cloudflare\|akamai\|fastly\|cloudfront"; then
        echo "⚠️  REVERSE PROXY DETECTED"
        echo "$headers" | grep -i "server\|x-cache" || true
    else
        echo "✓ No obvious reverse proxy"
    fi
    
    echo ""
}

recon_technology() {
    local domain=$1
    echo "=== TECHNOLOGY STACK ==="
    
    local headers
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)
    
    echo "Server:"
    echo "$headers" | grep -i "^server:" || echo "Hidden"
    
    echo -e "\nPowered By:"
    echo "$headers" | grep -i "x-powered-by:" || echo "Not disclosed"
    
    if check_tool whatweb; then
        echo -e "\nWhatWeb Analysis:"
        whatweb -q "$domain" 2>/dev/null || true
    fi
    
    echo ""
}

recon_sitemap() {
    local domain=$1
    echo "=== SITEMAP DISCOVERY ==="
    
    local sitemap_urls=(
        "https://$domain/sitemap.xml"
        "http://$domain/sitemap.xml"
        "https://$domain/robots.txt"
        "http://$domain/robots.txt"
    )
    
    for url in "${sitemap_urls[@]}"; do
        local status
        status=$(get_http_status "$url")
        if [[ "$status" == "200" ]]; then
            echo "Found: $url"
            curl -s "$url" 2>/dev/null | head -20 || true
        fi
    done
    
    echo ""
}

recon_headers() {
    local domain=$1
    echo "=== HTTP HEADERS ANALYSIS ==="
    
    local headers
    headers=$(curl -s -I "https://$domain" 2>/dev/null || curl -s -I "http://$domain" 2>/dev/null)
    
    echo "Full Headers:"
    echo "$headers"
    
    echo -e "\n=== SECURITY HEADERS ==="
    
    local security_headers=(
        "Strict-Transport-Security"
        "X-Content-Type-Options"
        "X-Frame-Options"
        "Content-Security-Policy"
    )
    
    for header in "${security_headers[@]}"; do
        if echo "$headers" | grep -qi "$header"; then
            echo "✓ $header: Present"
        else
            echo "✗ $header: Missing"
        fi
    done
    
    echo ""
}
