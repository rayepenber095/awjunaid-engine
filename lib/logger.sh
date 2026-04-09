#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/colors.sh"

# Initialize logging
init_logger() {
    local log_file=$1
    export LOG_FILE="$log_file"
}

# Log with timestamp
log_info() {
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[${timestamp}] [INFO]${NC} ${message}" | tee -a "$LOG_FILE"
}

log_success() {
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[${timestamp}] [✓]${NC} ${message}" | tee -a "$LOG_FILE"
}

log_warn() {
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[${timestamp}] [⚠]${NC} ${message}" | tee -a "$LOG_FILE"
}

log_error() {
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[${timestamp}] [✗]${NC} ${message}" | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "${VERBOSE:-0}" == "1" ]]; then
        local message="$*"
        local timestamp
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo -e "${MAGENTA}[${timestamp}] [DEBUG]${NC} ${message}" | tee -a "$LOG_FILE"
    fi
}
