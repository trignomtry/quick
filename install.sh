#!/usr/bin/env bash
set -euo pipefail

# QuickScript install helper
# Usage: curl -fsSL https://quick-script.dev/install.sh | sh

INSTALL_DIR="${INSTALL_DIR:-${HOME}/.quick/bin}"
QS_VERSION="${QS_VERSION:-latest}"
QS_BASE="${QS_BASE:-}"
GH_OWNER="${GH_OWNER:-trignomtry}"
GH_REPO="${GH_REPO:-quick}"

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    green="$(tput setaf 2)"
    yellow="$(tput setaf 3)"
    red="$(tput setaf 1)"
    reset="$(tput sgr0)"
else
    green=""; yellow=""; red=""; reset=""
fi

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

artifact_base="quick-${os}-${arch}"

if [ -z "${QS_BASE}" ]; then
    if [ "${QS_VERSION}" = "latest" ]; then
        base="https://github.com/${GH_OWNER}/${GH_REPO}/releases/latest/download"
    else
        base="https://github.com/${GH_OWNER}/${GH_REPO}/releases/download/${QS_VERSION}"
    fi
    artifact="${artifact_base}.tar.gz"
    download_target="${artifact}"
    unpack="tar"
else
    base="${QS_BASE%/}"
    artifact="${artifact_base}"
    download_target="${artifact}"
    unpack="none"
fi

url="${base}/${artifact}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

echo "Downloading ${artifact} from ${url}..."
if ! curl -fsSL "${url}" -o "${tmpdir}/${download_target}"; then
    echo "Download failed. Check QS_BASE/QS_VERSION or connectivity." >&2
    exit 1
fi

case "${unpack}" in
    tar)
        if ! tar -xzf "${tmpdir}/${download_target}" -C "${tmpdir}"; then
            echo "Failed to extract archive ${download_target}" >&2
            exit 1
        fi
        bin_src="${tmpdir}/${artifact_base}"
        ;;
    none)
        bin_src="${tmpdir}/${download_target}"
        ;;
esac

chmod +x "${bin_src}"

target_dir="${INSTALL_DIR%/}"
dest="${target_dir}/quick"
dest_dir="$(dirname "${dest}")"

ensure_writable_dir() {
    local dir="$1"
    mkdir -p "${dir}" 2>/dev/null || true
    [ -w "${dir}" ]
}

if ! ensure_writable_dir "${dest_dir}"; then
    if [ "${target_dir}" != "/usr/local/bin" ]; then
        echo "Install dir ${target_dir} not writable, trying /usr/local/bin"
        target_dir="/usr/local/bin"
        dest="${target_dir}/quick"
        dest_dir="$(dirname "${dest}")"
    fi

    if ! ensure_writable_dir "${dest_dir}"; then
        echo "${red}No writable install dir. Set INSTALL_DIR to a writable path (e.g. ${HOME}/.quick/bin) or run with sudo for a system path.${reset}" >&2
        exit 1
    fi
fi

if [ -e "${dest}" ] && [ ! -w "${dest}" ]; then
    echo "${red}Existing ${dest} is not writable. Remove it or set INSTALL_DIR to a writable location.${reset}" >&2
    exit 1
fi

install -m 755 "${bin_src}" "${dest}"

echo "${green}Installed to ${dest}${reset}"
case ":${PATH}:" in
    *:"${dest_dir}":*)
        echo "${green}${dest_dir}${reset} is already on your PATH."
        ;;
    *)
        echo "${yellow}${dest_dir} is not on your PATH.${reset}"
        echo "Add it with: ${yellow}echo 'export PATH=\"${dest_dir}:\$PATH\"' >> ~/.zprofile && source ~/.zprofile${reset}"
        ;;
esac
