#!/usr/bin/env bash
set -euo pipefail

# QuickScript install helper
# Usage: curl -fsSL https://quick-script.dev/install.sh | sh

QS_BASE="${QS_BASE:-https://quick-script.dev/dist/}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "${uname_s}" in
    Linux)   os="linux" ;;
    Darwin)  os="darwin" ;;
    *)       echo "Unsupported OS: ${uname_s}" >&2; exit 1 ;;
esac

case "${uname_m}" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="arm64" ;;
    *)            echo "Unsupported arch: ${uname_m}" >&2; exit 1 ;;
esac

artifact="quick-${os}-${arch}"
url="${QS_BASE}/${artifact}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

echo "Downloading ${artifact} from ${url}..."
if ! curl -fsSL "${url}" -o "${tmpdir}/quick"; then
    echo "Download failed. Check QS_BASE or connectivity." >&2
    exit 1
fi

chmod +x "${tmpdir}/quick"

dest="${INSTALL_DIR}/quick"
if [ ! -w "${INSTALL_DIR}" ]; then
    echo "Install dir ${INSTALL_DIR} not writable, trying ~/.local/bin"
    mkdir -p "${HOME}/.local/bin"
    dest="${HOME}/.local/bin/quick"
fi

mkdir -p "$(dirname "${dest}")"
mv "${tmpdir}/quick" "${dest}"

echo "Installed to ${dest}"
echo "Ensure it is on your PATH. Current PATH: ${PATH}"
