#!/bin/bash

##############################################################################
# OreNPMGuard - Shai-Hulud Package Blocker Script
#
# A comprehensive security tool to detect and block Shai-Hulud compromised
# npm packages across any Unix environment.
#
# Repository: https://github.com/rapticore/orenpmpguard
# Contact: contact@rapticore.com
#
# Usage: ./block-shai-hulud.sh [OPTIONS] [TARGET]
##############################################################################

set -euo pipefail

# Script metadata
SCRIPT_NAME="OreNPMGuard Shai-Hulud Blocker"
SCRIPT_VERSION="1.0.0"
SCRIPT_AUTHOR="Rapticore Security"
SCRIPT_URL="https://github.com/rapticore/OreNPMGuard"

# Color codes for output
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    PURPLE=''
    CYAN=''
    WHITE=''
    BOLD=''
    NC=''
fi

# Default settings
QUIET_MODE=false
FAIL_FAST=true
SCAN_TARGET="."
TEMP_DIR=""
EXIT_CODE=0
CRITICAL_FOUND=false
WARNING_FOUND=false

# Critical packages that should immediately fail builds
CRITICAL_PACKAGES=(
    "@ctrl/deluge"
    "@ctrl/tinycolor"
    "ngx-bootstrap"
    "rxnt-authentication"
)

##############################################################################
# Helper Functions
##############################################################################

log_info() {
    if [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${BLUE}ℹ️  ${NC}$1"
    fi
}

log_success() {
    if [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${GREEN}✅ ${NC}$1"
    fi
}

log_warning() {
    echo -e "${YELLOW}⚠️  WARNING: ${NC}$1" >&2
}

log_error() {
    echo -e "${RED}❌ ERROR: ${NC}$1" >&2
}

log_critical() {
    echo -e "${RED}🚨 CRITICAL SECURITY ALERT: ${NC}$1" >&2
}

print_header() {
    if [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "${BOLD}${CYAN}"
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║                     🛡️  OreNPMGuard - Shai-Hulud Blocker                    ║"
        echo "║                                                                              ║"
        echo "║  Comprehensive security scanner for Shai-Hulud supply chain attack         ║"
        echo "║  Repository: https://github.com/rapticore/orenpmpguard                      ║"
        echo "║  Contact: contact@rapticore.com                                             ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo
    fi
}

print_usage() {
    cat << EOF
${BOLD}USAGE:${NC}
    $0 [OPTIONS] [TARGET]

${BOLD}DESCRIPTION:${NC}
    Scans for npm packages compromised in the Shai-Hulud supply chain attack.
    Supports scanning package.json, package-lock.json files, and directories.

${BOLD}OPTIONS:${NC}
    -h, --help          Show this help message
    -v, --version       Show version information
    -q, --quiet         Quiet mode (minimal output)
    -f, --file FILE     Scan specific file (package.json or package-lock.json)
    -d, --directory DIR Scan directory recursively
    --fail-fast         Exit immediately on critical packages (default)
    --no-fail-fast      Continue scanning even if critical packages found
    --check-only        Only check, don't perform remediation actions

${BOLD}TARGETS:${NC}
    FILE                Path to package.json or package-lock.json file
    DIRECTORY           Path to directory to scan recursively (default: current directory)

${BOLD}EXIT CODES:${NC}
    0                   No compromised packages found
    1                   Critical packages found (immediate action required)
    2                   Warning packages found (review recommended)
    3                   Script error or invalid usage

${BOLD}EXAMPLES:${NC}
    $0                              # Scan current directory
    $0 /path/to/project             # Scan specific directory
    $0 -f package.json              # Scan specific package.json file
    $0 -q --fail-fast .             # Quiet mode, exit on first critical package
    $0 --no-fail-fast /projects     # Scan all, don't exit early

${BOLD}SECURITY CONTACT:${NC}
    Emergency: contact@rapticore.com
    Repository: https://github.com/rapticore/orenpmpguard

EOF
}

cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

##############################################################################
# Package Detection Functions
##############################################################################

download_scanner() {
    log_info "Downloading latest OreNPMGuard scanner..."

    TEMP_DIR=$(mktemp -d)

    # Download scanner files
    if ! curl -sSL https://raw.githubusercontent.com/rapticore/OreNPMGuard/main/shai_hulud_scanner.py -o "$TEMP_DIR/shai_hulud_scanner.py"; then
        log_error "Failed to download Python scanner"
        return 1
    fi

    if ! curl -sSL https://raw.githubusercontent.com/rapticore/OreNPMGuard/main/affected_packages.yaml -o "$TEMP_DIR/affected_packages.yaml"; then
        log_error "Failed to download package database"
        return 1
    fi

    chmod +x "$TEMP_DIR/shai_hulud_scanner.py"
    log_success "Scanner downloaded successfully"
}

check_dependencies() {
    local missing_deps=()

    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi

    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Please install missing dependencies and try again"
        return 1
    fi

    # Check for PyYAML
    if ! python3 -c "import yaml" 2>/dev/null; then
        log_warning "PyYAML not found. Installing..."
        if command -v pip3 &> /dev/null; then
            pip3 install pyyaml --quiet
        elif command -v pip &> /dev/null; then
            pip install pyyaml --quiet
        else
            log_error "Cannot install PyYAML. Please install manually: pip install pyyaml"
            return 1
        fi
    fi
}

scan_file() {
    local file_path="$1"
    local file_type=""

    if [[ "$file_path" == *"package.json" ]]; then
        file_type="📦"
    elif [[ "$file_path" == *"package-lock.json" ]]; then
        file_type="🔒"
    else
        log_error "Unsupported file type: $file_path"
        return 1
    fi

    if [[ ! -f "$file_path" ]]; then
        log_error "File not found: $file_path"
        return 1
    fi

    log_info "${file_type} Scanning: $file_path"

    # Run the scanner and capture output
    local scan_output
    if scan_output=$(python3 "$TEMP_DIR/shai_hulud_scanner.py" "$file_path" 2>&1); then

        # Check for critical packages
        if echo "$scan_output" | grep -q "🚨 CRITICAL"; then
            CRITICAL_FOUND=true
            log_critical "Compromised packages detected in $file_path!"

            if [[ "$QUIET_MODE" != "true" ]]; then
                echo "$scan_output" | grep -A 10 "🚨 CRITICAL"
            fi

            # Check if any critical packages are in our high-priority list
            for critical_pkg in "${CRITICAL_PACKAGES[@]}"; do
                if echo "$scan_output" | grep -q "$critical_pkg"; then
                    log_critical "High-priority package detected: $critical_pkg"
                    if [[ "$FAIL_FAST" == "true" ]]; then
                        log_critical "Failing immediately due to critical package"
                        exit 1
                    fi
                fi
            done

        elif echo "$scan_output" | grep -q "⚠️ WARNING"; then
            WARNING_FOUND=true
            log_warning "Potential threats detected in $file_path"

            if [[ "$QUIET_MODE" != "true" ]]; then
                echo "$scan_output" | grep -A 10 "⚠️ WARNING"
            fi

        else
            log_success "Clean: $file_path"
        fi

    else
        log_error "Scanner failed for $file_path"
        return 1
    fi
}

scan_directory() {
    local dir_path="$1"
    local files_found=0

    if [[ ! -d "$dir_path" ]]; then
        log_error "Directory not found: $dir_path"
        return 1
    fi

    log_info "🔍 Scanning directory: $dir_path"

    # Find package.json files
    while IFS= read -r -d '' file; do
        ((files_found++))
        scan_file "$file"
    done < <(find "$dir_path" -name "package.json" -not -path "*/node_modules/*" -print0)

    # Find package-lock.json files
    while IFS= read -r -d '' file; do
        ((files_found++))
        scan_file "$file"
    done < <(find "$dir_path" -name "package-lock.json" -not -path "*/node_modules/*" -print0)

    if [[ $files_found -eq 0 ]]; then
        log_warning "No package.json or package-lock.json files found in $dir_path"
    else
        log_info "Scanned $files_found files total"
    fi
}

generate_report() {
    local timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

    echo
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}                            SECURITY SCAN SUMMARY${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${BOLD}Scan Details:${NC}"
    echo "  • Target: $SCAN_TARGET"
    echo "  • Timestamp: $timestamp"
    echo "  • Scanner: $SCRIPT_NAME v$SCRIPT_VERSION"
    echo

    if [[ "$CRITICAL_FOUND" == "true" ]]; then
        echo -e "${RED}${BOLD}🚨 CRITICAL SECURITY ALERT${NC}"
        echo
        echo -e "${RED}Shai-Hulud compromised packages detected!${NC}"
        echo
        echo -e "${BOLD}IMMEDIATE ACTIONS REQUIRED:${NC}"
        echo "  1. 🛑 STOP all development work on affected projects"
        echo "  2. 📦 Remove compromised packages: npm uninstall <package-name>"
        echo "  3. 🧹 Clear npm cache: npm cache clean --force"
        echo "  4. 🗂️  Delete node_modules: rm -rf node_modules && npm install"
        echo "  5. 🔑 Rotate ALL credentials:"
        echo "     • GitHub Personal Access Tokens"
        echo "     • npm Authentication Tokens"
        echo "     • SSH Keys"
        echo "     • API Keys (AWS, Atlassian, Datadog, etc.)"
        echo "  6. 🔍 Investigation:"
        echo "     • Check GitHub for public repos named 'Shai-Hulud'"
        echo "     • Look for repos with '-migration' suffix"
        echo "     • Review GitHub audit logs"
        echo "     • Check for branches named 'shai-hulud'"
        echo
        echo -e "${BOLD}Emergency Contact:${NC} contact@rapticore.com"
        echo -e "${BOLD}Documentation:${NC} $SCRIPT_URL"

        EXIT_CODE=1

    elif [[ "$WARNING_FOUND" == "true" ]]; then
        echo -e "${YELLOW}${BOLD}⚠️  WARNING: Potential Threats Detected${NC}"
        echo
        echo "Package name matches found with different versions."
        echo "Review recommended to ensure safety."
        echo
        echo -e "${BOLD}Recommended Actions:${NC}"
        echo "  1. 📋 Review flagged packages carefully"
        echo "  2. 🔍 Verify package versions and sources"
        echo "  3. 🔄 Update to latest safe versions if available"
        echo "  4. 📞 Contact security team if unsure"
        echo

        EXIT_CODE=2

    else
        echo -e "${GREEN}${BOLD}✅ SCAN PASSED${NC}"
        echo
        echo "No Shai-Hulud compromised packages detected."
        echo "All scanned files are clean."
        echo
        echo -e "${BOLD}Repository Status:${NC} ${GREEN}SAFE FOR DEPLOYMENT${NC}"

        EXIT_CODE=0
    fi

    echo
    echo -e "${BOLD}Resources:${NC}"
    echo "  • Scanner Repository: $SCRIPT_URL"
    echo "  • Attack Information: $SCRIPT_URL#about-the-shai-hulud-attack"
    echo "  • Security Contact: contact@rapticore.com"
    echo
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
}

##############################################################################
# Main Script Logic
##############################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_usage
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                echo "Author: $SCRIPT_AUTHOR"
                echo "Repository: $SCRIPT_URL"
                exit 0
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -f|--file)
                if [[ -n "${2:-}" ]]; then
                    SCAN_TARGET="$2"
                    shift 2
                else
                    log_error "Option --file requires an argument"
                    exit 3
                fi
                ;;
            -d|--directory)
                if [[ -n "${2:-}" ]]; then
                    SCAN_TARGET="$2"
                    shift 2
                else
                    log_error "Option --directory requires an argument"
                    exit 3
                fi
                ;;
            --fail-fast)
                FAIL_FAST=true
                shift
                ;;
            --no-fail-fast)
                FAIL_FAST=false
                shift
                ;;
            --check-only)
                # Future feature for read-only checking
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                print_usage
                exit 3
                ;;
            *)
                SCAN_TARGET="$1"
                shift
                ;;
        esac
    done

    # Print header unless in quiet mode
    print_header

    # Check dependencies
    if ! check_dependencies; then
        exit 3
    fi

    # Download scanner
    if ! download_scanner; then
        exit 3
    fi

    # Determine scan type and execute
    if [[ -f "$SCAN_TARGET" ]]; then
        scan_file "$SCAN_TARGET"
    elif [[ -d "$SCAN_TARGET" ]]; then
        scan_directory "$SCAN_TARGET"
    else
        log_error "Target not found or not accessible: $SCAN_TARGET"
        exit 3
    fi

    # Generate final report
    generate_report

    # Exit with appropriate code
    exit $EXIT_CODE
}

# Execute main function with all arguments
main "$@"