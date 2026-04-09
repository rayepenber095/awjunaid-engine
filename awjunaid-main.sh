#!/usr/bin/env bash

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source all modules
source "${SCRIPT_DIR}/lib/colors.sh"
source "${SCRIPT_DIR}/lib/logger.sh"
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/modules/recon.sh"
source "${SCRIPT_DIR}/modules/enumeration.sh"
source "${SCRIPT_DIR}/modules/scanning.sh"
source "${SCRIPT_DIR}/modules/exploitation.sh"
source "${SCRIPT_DIR}/modules/reporting.sh"

# Global variables
DOMAIN=""
SCAN_MODE="medium"
THREADS=10
VERBOSE=0
START_TIME=$(date +%s)

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
 ___     ___       __  __  __  ___  __   __     __  ___  ____
|  _)   / __)  _  (  )(  )(  )(  _)(  ) (  )   / _ \(  _)(    \
| |    ( (___ / \ ) (  ) (  ) ( ) _) (/ (_/   ( (_) ))__)  ) D (
|_|     \___)\_/ (__) (__)(__)(___)(_/\_)_)    \___/(____)(____)

        AWJUNAID SCRIPT ENGINE v2.0
        Professional Bug Bounty Automation
EOF
    echo -e "${NC}"
}

print_help() {
    cat << EOF
${CYAN}AWJUNAID Script Engine v2.0${NC} - Bug Bounty Automation Framework

${GREEN}Usage:${NC}
  bash awjunaid-main.sh -d <domain> [OPTIONS]

${GREEN}Required Arguments:${NC}
  -d, --domain <domain>          Target domain to scan

${GREEN}Optional Arguments:${NC}
  -m, --mode <mode>              Scan mode: soft, medium (default), hard
  -t, --threads <number>         Number of threads (default: 10)
  -v, --verbose                  Verbose output
  -h, --help                     Show this help message

${GREEN}Examples:${NC}
  bash awjunaid-main.sh -d example.com -m soft
  bash awjunaid-main.sh -d example.com -m medium -t 20
  bash awjunaid-main.sh -d example.com -m hard -v

EOF
}

main() {
    print_banner
    
    if [[ $# -eq 0 ]]; then
        print_help
        exit 1
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -m|--mode)
                SCAN_MODE="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                export VERBOSE
                shift
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done
    
    # Validate
    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi
    
    # Create output directory
    OUTPUT_DIR=$(create_output_dir "$DOMAIN")
    LOG_FILE="${OUTPUT_DIR}/scan.log"
    init_logger "$LOG_FILE"
    
    log_success "AWJUNAID Script Engine v2.0 initialized"
    log_info "Domain: $DOMAIN | Mode: $SCAN_MODE | Output: $OUTPUT_DIR"
    
    # Execute 5-phase workflow
    recon_phase "$DOMAIN" "$OUTPUT_DIR"
    enumeration_phase "$DOMAIN" "$OUTPUT_DIR"
    scanning_phase "$DOMAIN" "$OUTPUT_DIR" "$SCAN_MODE"
    exploitation_phase "$DOMAIN" "$OUTPUT_DIR"
    reporting_phase "$DOMAIN" "$OUTPUT_DIR" "$START_TIME"
    
    # Print summary
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}              ${GREEN}✓ SCAN COMPLETED${NC}${CYAN}                   ║${NC}"
    echo -e "${CYAN}║${NC} Target: ${WHITE}$DOMAIN${NC}${CYAN}                    ║${NC}"
    echo -e "${CYAN}║${NC} Duration: ${WHITE}${duration}s${NC}${CYAN}                          ║${NC}"
    echo -e "${CYAN}║${NC} Reports: ${WHITE}$OUTPUT_DIR${NC}${CYAN} ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_success "Scan completed!"
}

main "$@"
