#!/bin/bash
# mmwx-speedtester install & run script
# Usage: curl -fsSL <url>/install.sh | bash -s -- -master https://your-master-url -token <token>
set -e

REPO="MMWOrg/mmwX-plugins"
BINARY_NAME="mmwx-speedtester"
INSTALL_DIR="."

# Parse arguments
MASTER=""
TOKEN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -master) MASTER="$2"; shift 2 ;;
    -token) TOKEN="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [ -z "$MASTER" ] || [ -z "$TOKEN" ]; then
  echo "Usage: bash install.sh -master <master-url> -token <token>"
  exit 1
fi

# Detect OS and architecture
detect_platform() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"

  case "$OS" in
    linux) OS="linux" ;;
    # 我也不知道为什么op tr '[:upper:]' '[:lower:]')" 后变成了Linlx
    Linlx) OS="linux" ;;
    darwin) OS="darwin" ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
  esac

  case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
  esac
}

# Get download URL from latest release
get_download_url() {
  local asset_name="${BINARY_NAME}-${OS}-${ARCH}"
  if [ "$OS" = "windows" ]; then
    asset_name="${asset_name}.exe"
  fi

  echo "Fetching latest release..."
  local release_url="https://api.github.com/repos/${REPO}/releases/latest"
  local release_json
  release_json=$(curl -fsSL "$release_url") || {
    echo "Failed to fetch release info"; exit 1
  }

  DOWNLOAD_URL=$(echo "$release_json" | grep -o "\"browser_download_url\": *\"[^\"]*${asset_name}\"" | head -1 | cut -d'"' -f4)
  if [ -z "$DOWNLOAD_URL" ]; then
    echo "Asset ${asset_name} not found."
    echo "Visit https://github.com/${REPO}/releases/latest to download manually."
    exit 1
  fi

  VERSION=$(echo "$release_json" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
  echo "Latest version: ${VERSION}"
}

# Download binary
download_binary() {
  local output="${INSTALL_DIR}/${BINARY_NAME}"
  if [ "$OS" = "windows" ]; then
    output="${output}.exe"
  fi

  echo "Downloading ${BINARY_NAME} (${OS}/${ARCH})..."
  curl -fsSL -o "$output" "$DOWNLOAD_URL" || {
    echo "Download failed"; exit 1
  }
  chmod +x "$output"
  echo "Saved to: ${output}"
  BINARY_PATH="$output"
}

# Run
run_binary() {
  echo ""
  echo "========================================"
  echo "Master: ${MASTER}"
  echo "========================================"
  echo ""
  exec "$BINARY_PATH" -master "$MASTER" -token "$TOKEN"
}

detect_platform
get_download_url
download_binary
run_binary
