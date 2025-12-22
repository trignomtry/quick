#!/usr/bin/env bash
set -euo pipefail

LLVM_TAG=${LLVM_TAG:-llvmorg-18.1.4}
LLVM_VERSION=${LLVM_TAG#llvmorg-}
PREFIX=${LLVM_PREFIX:-$(pwd)/llvm/install}

os=$(uname -s)
arch=$(uname -m)
platform=""
tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

if [ -n "${LLVM_ARCHIVE:-}" ]; then
  archives=("${LLVM_ARCHIVE}")
else
  case "${os}" in
    Linux)
      case "${arch}" in
        x86_64|amd64)
          platform="x86_64-linux-gnu"
          fallback_archives=(
            "clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-22.04.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-20.04.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu.tar.xz"
          )
          ;;
        aarch64|arm64)
          platform="aarch64-linux-gnu"
          fallback_archives=(
            "clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu.tar.xz"
            "clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu-ubuntu-22.04.tar.xz"
            "clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu-ubuntu-20.04.tar.xz"
            "clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu-ubuntu-18.04.tar.xz"
          )
          ;;
        *)
          echo "Unsupported Linux arch: ${arch}" >&2
          exit 1
          ;;
      esac
      ;;
    Darwin)
      case "${arch}" in
        arm64)
          platform="arm64-apple-darwin"
          fallback_archives=(
            "clang+llvm-${LLVM_VERSION}-arm64-apple-darwin23.0.tar.xz"
            "clang+llvm-${LLVM_VERSION}-arm64-apple-darwin22.0.tar.xz"
          )
          ;;
        x86_64)
          platform="x86_64-apple-darwin"
          fallback_archives=(
            "clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin22.0.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin21.0.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin20.0.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin19.0.tar.xz"
          )
          ;;
        *)
          echo "Unsupported macOS arch: ${arch}" >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "Unsupported OS: ${os}" >&2
      exit 1
      ;;
  esac
fi

archives=()
sha_list=""
sha_url="https://github.com/llvm/llvm-project/releases/download/${LLVM_TAG}/SHA256SUMS"
if [ -z "${LLVM_ARCHIVE:-}" ]; then
  if curl -fsSL "${sha_url}" -o "${tmpdir}/llvm-SHA256SUMS"; then
    sha_list="${tmpdir}/llvm-SHA256SUMS"
  fi
fi

if [ -n "${LLVM_ARCHIVE:-}" ]; then
  archives=("${LLVM_ARCHIVE}")
elif [ -n "${sha_list}" ] && [ -n "${platform}" ]; then
  while IFS= read -r entry; do
    archives+=("${entry}")
  done < <(awk '{print $2}' "${sha_list}" | grep "clang+llvm-${LLVM_VERSION}-${platform}" || true)
fi

if [ ${#archives[@]} -eq 0 ]; then
  archives=(${fallback_archives[@]})
fi

archive_file=""
for archive in "${archives[@]}"; do
  url="https://github.com/llvm/llvm-project/releases/download/${LLVM_TAG}/${archive}"
  echo "Trying LLVM download: ${url}" >&2
  if curl -fsSL "${url}" -o "${tmpdir}/${archive}"; then
    archive_file="${tmpdir}/${archive}"
    break
  else
    echo "Download failed for ${archive}, trying next candidate" >&2
  fi
done

if [ -z "${archive_file}" ]; then
  if [ "${os}" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    echo "No prebuilt LLVM archive found; falling back to Homebrew llvm@18" >&2
    brew install llvm@18
    brew_prefix=$(brew --prefix llvm@18)
    if [ -z "${brew_prefix}" ] || [ ! -d "${brew_prefix}" ]; then
      echo "Homebrew llvm@18 prefix not found" >&2
      exit 1
    fi
    rm -rf "${PREFIX}"
    mkdir -p "${PREFIX}"
    cp -R "${brew_prefix}"/* "${PREFIX}/"
    echo "LLVM installed via Homebrew to ${PREFIX}" >&2
    exit 0
  fi

  echo "Failed to download LLVM archive; tried: ${archives[*]}" >&2
  exit 1
fi

echo "Extracting $(basename "${archive_file}")" >&2
if ! tar -xJf "${archive_file}" -C "${tmpdir}"; then
  echo "Failed to extract ${archive_file}" >&2
  exit 1
fi

extracted_dir=$(find "${tmpdir}" -maxdepth 1 -type d -name "clang+llvm-*" | head -n1)
if [ -z "${extracted_dir}" ]; then
  echo "Extracted LLVM directory not found" >&2
  exit 1
fi

rm -rf "${PREFIX}"
mkdir -p "${PREFIX}"
cp -R "${extracted_dir}"/* "${PREFIX}/"

if [ ! -x "${PREFIX}/bin/llvm-config" ]; then
  echo "llvm-config not found under ${PREFIX}; installation incomplete" >&2
  exit 1
fi

echo "LLVM installed to ${PREFIX}" >&2
