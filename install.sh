#!/bin/sh
# install.sh - Install docker-credential-passage
# Usage: curl -fsSL https://raw.githubusercontent.com/amrkmn/docker-credential-passage/main/install.sh | sh

set -e

REPO="amrkmn/docker-credential-passage"
BINARY_NAME="docker-credential-passage"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log functions
log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "darwin";;
        *)          echo "unknown";;
    esac
}

# Detect architecture
detect_arch() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   echo "amd64";;
        arm64|aarch64)  echo "arm64";;
        armv7l|armv7)   echo "arm";;
        i386|i686)      echo "386";;
        *)              echo "unknown";;
    esac
}

# Get latest release version
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

# Main installation
main() {
    log_info "Installing ${BINARY_NAME}..."
    
    # Check if already installed in INSTALL_DIR
    EXISTING_BINARY="${INSTALL_DIR}/${BINARY_NAME}"
    if [ -x "$EXISTING_BINARY" ]; then
        INSTALLED_VERSION="$($EXISTING_BINARY version 2>/dev/null | head -1 || echo "")"
        if [ -n "$INSTALLED_VERSION" ]; then
            # Get version to install
            if [ -n "$VERSION" ]; then
                TARGET_VERSION="v${VERSION#v}"
            else
                TARGET_VERSION="$(get_latest_version)"
            fi
            
            # Extract version numbers for comparison (remove 'v' prefix if present)
            INSTALLED_VER_NUM=$(echo "$INSTALLED_VERSION" | sed -E 's/^v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
            TARGET_VER_NUM=$(echo "$TARGET_VERSION" | sed -E 's/^v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/')
            
            if [ "$INSTALLED_VER_NUM" = "$TARGET_VER_NUM" ]; then
                log_info "Already installed and up to date: ${BINARY_NAME} ${INSTALLED_VERSION}"
                log_info "Installation skipped."
                exit 0
            else
                log_info "Update available: ${INSTALLED_VERSION} -> ${TARGET_VERSION}"
            fi
        fi
    fi
    
    # Detect platform
    OS="$(detect_os)"
    ARCH="$(detect_arch)"
    
    if [ "$OS" = "unknown" ]; then
        log_error "Unsupported operating system: $(uname -s)"
        exit 1
    fi
    
    if [ "$ARCH" = "unknown" ]; then
        log_error "Unsupported architecture: $(uname -m)"
        exit 1
    fi
    
    log_info "Detected platform: ${OS}/${ARCH}"
    
    # Get version
    if [ -n "$VERSION" ]; then
        VERSION="${VERSION#v}"  # Remove 'v' prefix if present
        VERSION="v${VERSION}"
    else
        log_info "Fetching latest release..."
        VERSION="$(get_latest_version)"
    fi
    
    log_info "Installing version: ${VERSION}"
    
    # Construct download URLs
    ASSET_NAME="${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    CHECKSUM_NAME="${ASSET_NAME}.sha256"
    
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/${CHECKSUM_NAME}"
    
    # Create temp directory
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT
    
    # Download binary
    log_info "Downloading ${ASSET_NAME}..."
    if ! curl -fsSL -o "${TMP_DIR}/${ASSET_NAME}" "$DOWNLOAD_URL"; then
        log_error "Failed to download ${ASSET_NAME}"
        log_error "URL: ${DOWNLOAD_URL}"
        exit 1
    fi
    
    # Download checksum
    log_info "Downloading checksum..."
    if ! curl -fsSL -o "${TMP_DIR}/${CHECKSUM_NAME}" "$CHECKSUM_URL"; then
        log_warn "Failed to download checksum, skipping verification"
    else
        # Verify checksum
        log_info "Verifying checksum..."
        cd "$TMP_DIR"
        if command -v sha256sum >/dev/null 2>&1; then
            if ! sha256sum -c "${CHECKSUM_NAME}" >/dev/null 2>&1; then
                log_error "Checksum verification failed"
                exit 1
            fi
        elif command -v shasum >/dev/null 2>&1; then
            if ! shasum -a 256 -c "${CHECKSUM_NAME}" >/dev/null 2>&1; then
                log_error "Checksum verification failed"
                exit 1
            fi
        else
            log_warn "Neither sha256sum nor shasum found, skipping verification"
        fi
        cd - >/dev/null
    fi
    
    # Extract binary
    log_info "Extracting binary..."
    tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "$TMP_DIR"
    
    # Check if extracted binary exists (archive contains binary with platform suffix)
    EXTRACTED_BINARY="${BINARY_NAME}-${OS}-${ARCH}"
    if [ ! -f "${TMP_DIR}/${EXTRACTED_BINARY}" ]; then
        log_error "Binary not found in archive"
        exit 1
    fi
    
    # Check install directory
    if [ ! -d "$INSTALL_DIR" ]; then
        log_info "Creating install directory: ${INSTALL_DIR}"
        if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
            log_error "Failed to create ${INSTALL_DIR}"
            log_error "Try running with sudo or set INSTALL_DIR to a writable directory"
            exit 1
        fi
    fi
    
    # Check if we need sudo
    USE_SUDO=""
    if [ ! -w "$INSTALL_DIR" ]; then
        if command -v sudo >/dev/null 2>&1; then
            USE_SUDO="sudo"
            log_info "Using sudo to install to ${INSTALL_DIR}"
        else
            log_error "Cannot write to ${INSTALL_DIR} and sudo not available"
            log_error "Try: INSTALL_DIR=~/.local/bin sh install.sh"
            exit 1
        fi
    fi
    
    # Install binary
    log_info "Installing to ${INSTALL_DIR}..."
    if ! $USE_SUDO cp "${TMP_DIR}/${EXTRACTED_BINARY}" "${INSTALL_DIR}/${BINARY_NAME}"; then
        log_error "Failed to install binary"
        exit 1
    fi
    
    # Make executable
    if ! $USE_SUDO chmod +x "${INSTALL_DIR}/${BINARY_NAME}"; then
        log_error "Failed to make binary executable"
        exit 1
    fi
    
    # Verify installation
    if command -v "${BINARY_NAME}" >/dev/null 2>&1; then
        INSTALLED_VERSION="$(${BINARY_NAME} version 2>/dev/null || echo "unknown")"
        log_info "Successfully installed ${BINARY_NAME} ${INSTALLED_VERSION}"
    elif [ -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        log_info "Successfully installed ${BINARY_NAME} to ${INSTALL_DIR}"
        log_warn "${INSTALL_DIR} is not in your PATH"
        log_warn "Add it to your PATH: export PATH=\"${INSTALL_DIR}:\$PATH\""
    else
        log_error "Installation may have failed"
        exit 1
    fi
    
    log_info "Installation complete!"
    log_info ""
    log_info "Next steps:"
    log_info "  1. Set up an identity: ${BINARY_NAME} setup identity [name]"
    log_info "  2. Configure Docker to use the helper"
    log_info "  3. Login to a registry: docker login <registry>"
}

# Show help
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    echo "Install docker-credential-passage"
    echo ""
    echo "Usage:"
    echo "  curl -fsSL https://raw.githubusercontent.com/amrkmn/docker-credential-passage/main/install.sh | sh"
    echo ""
    echo "Environment variables:"
    echo "  VERSION       - Specific version to install (e.g., 0.1.3)"
    echo "  INSTALL_DIR   - Installation directory (default: /usr/local/bin)"
    echo ""
    echo "Examples:"
    echo "  # Install latest version"
    echo "  curl -fsSL https://raw.githubusercontent.com/amrkmn/docker-credential-passage/main/install.sh | sh"
    echo ""
    echo "  # Install specific version"
    echo "  VERSION=0.1.2 curl -fsSL https://raw.githubusercontent.com/amrkmn/docker-credential-passage/main/install.sh | sh"
    echo ""
    echo "  # Install to custom directory"
    echo "  INSTALL_DIR=~/.local/bin curl -fsSL https://raw.githubusercontent.com/amrkmn/docker-credential-passage/main/install.sh | sh"
    exit 0
fi

main "$@"
