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
    blue="$(tput setaf 4)"
    bold="$(tput bold)"
    reset="$(tput sgr0)"
else
    green=""; yellow=""; red=""; blue=""; bold=""; reset=""
fi

info()   { echo "${blue}==>${reset} ${bold}$*${reset}"; }
warn()   { echo "${yellow}!!${reset} ${bold}$*${reset}"; }
error()  { echo "${red}xx${reset} ${bold}$*${reset}" >&2; }
success(){ echo "${green}ok${reset} ${bold}$*${reset}"; }

ensure_llvm() {
    if command -v llvm-config >/dev/null 2>&1; then
        info "LLVM already available ($(llvm-config --version 2>/dev/null | head -n1))"
        return
    fi

    if command -v brew >/dev/null 2>&1; then
        info "Installing LLVM via Homebrew (llvm@18)"
        if brew install llvm@18; then
            success "LLVM installed via Homebrew"
            return
        else
            warn "Homebrew install failed, trying direct download"
        fi
    fi

    if [ "${os}" != "darwin" ]; then
        warn "Please install LLVM 18+ using your package manager (e.g. apt/yum)"
        return
    fi

    case "${arch}" in
        arm64)
            llvm_pkg="clang+llvm-18.1.8-arm64-apple-darwin23.0.tar.xz"
            ;;
        x86_64)
            llvm_pkg="clang+llvm-18.1.8-x86_64-apple-darwin20.0.tar.xz"
            ;;
    esac

    llvm_url="https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/${llvm_pkg}"
    llvm_dir="${HOME}/.quick/llvm"
    mkdir -p "${llvm_dir}" 2>/dev/null || true
    info "Downloading LLVM toolchain from ${llvm_url}"
    if curl -fsSL "${llvm_url}" -o "${tmpdir}/${llvm_pkg}"; then
        if tar -xJf "${tmpdir}/${llvm_pkg}" -C "${tmpdir}"; then
            extracted="${tmpdir}/${llvm_pkg%.tar.xz}"
            cp -R "${extracted}"/* "${llvm_dir}"/
            success "LLVM unpacked to ${llvm_dir}"
            warn "Add LLVM to PATH with: export PATH=\"${llvm_dir}/bin:$PATH\""
        else
            warn "Failed to extract ${llvm_pkg}; please install LLVM manually"
        fi
    else
        warn "Failed to download LLVM; please install LLVM 18+ manually"
    fi
}

uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "${uname_s}" in
    Linux)   os="linux" ;;
    Darwin)  os="darwin" ;;
    *)       error "Unsupported OS: ${uname_s}"; exit 1 ;;
esac

case "${uname_m}" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="arm64" ;;
    *)            error "Unsupported arch: ${uname_m}"; exit 1 ;;
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

info "QuickScript installer"
info "Target: ${os}/${arch}"
info "Install dir: ${INSTALL_DIR%/}"
echo

ensure_llvm

info "Downloading ${artifact} from ${url}..."
if ! curl -fsSL "${url}" -o "${tmpdir}/${download_target}"; then
    error "Download failed. Check QS_BASE/QS_VERSION or connectivity."
    exit 1
fi

case "${unpack}" in
    tar)
        if ! tar -xzf "${tmpdir}/${download_target}" -C "${tmpdir}"; then
            error "Failed to extract archive ${download_target}"
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
        warn "Install dir ${target_dir} not writable, trying /usr/local/bin"
        target_dir="/usr/local/bin"
        dest="${target_dir}/quick"
        dest_dir="$(dirname "${dest}")"
    fi

    if ! ensure_writable_dir "${dest_dir}"; then
        error "No writable install dir. Set INSTALL_DIR to a writable path (e.g. ${HOME}/.quick/bin) or run with sudo for a system path."
        exit 1
    fi
fi

if [ -e "${dest}" ] && [ ! -w "${dest}" ]; then
    error "Existing ${dest} is not writable. Remove it or set INSTALL_DIR to a writable location."
    exit 1
fi

install -m 755 "${bin_src}" "${dest}"

success "Installed to ${dest}"
case ":${PATH}:" in
    *:"${dest_dir}":*)
        success "${dest_dir} is already on your PATH."
        ;;
    *)
        warn "${dest_dir} is not on your PATH."
        echo "Add it with:"
        echo "  ${yellow}echo 'export PATH=\"${dest_dir}:\$PATH\"' >> ~/.zprofile && source ~/.zprofile${reset}"
        ;;
esac
