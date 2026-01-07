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

maybe_prompt_clt() {
    if [ "${os}" != "darwin" ]; then
        return
    fi
    if xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1; then
        return
    fi

    warn "Apple Command Line Tools not detected."
    warn "Sketch (JIT) works without CLT, but Ship (AOT) requires it."

    if [ -t 0 ]; then
        printf "Install Command Line Tools now? [y/N]: "
        read -r reply || reply=""
        case "$reply" in
            [Yy]*)
                info "Launching xcode-select --install (follow the GUI prompt, then rerun this installer)."
                xcode-select --install || true
                exit 0
                ;;
            *)
                warn "Skipping CLT install. Ship/AOT will not work until you run 'xcode-select --install'."
                ;;
        esac
    else
        warn "Non-interactive shell; run 'xcode-select --install' to enable Ship/AOT mode."
    fi
}

maybe_prompt_clt



info "Downloading ${artifact} from ${url}..."
if ! curl -#fsSL "${url}" -o "${tmpdir}/${download_target}"; then
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

# Install bundled toolchain binaries for AOT into INSTALL_DIR
for tool in clang ld.lld lld llvm-ar llvm-ranlib; do
    if [ -f "${tmpdir}/llvm/bin/${tool}" ]; then
        install -m 755 "${tmpdir}/llvm/bin/${tool}" "${target_dir}/${tool}"
    fi
done

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
