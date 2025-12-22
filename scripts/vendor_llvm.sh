#!/usr/bin/env bash
set -euo pipefail

LLVM_TAG=${LLVM_TAG:-llvmorg-18.1.8}
LLVM_VERSION=${LLVM_TAG#llvmorg-}
PREFIX=${LLVM_PREFIX:-$(pwd)/llvm/install}

os=$(uname -s)
arch=$(uname -m)

if [ -n "${LLVM_ARCHIVE:-}" ]; then
  archives=("${LLVM_ARCHIVE}")
else
  case "${os}" in
    Linux)
      case "${arch}" in
        x86_64|amd64)
          archives=(
            "clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-22.04.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-20.04.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu.tar.xz"
          )
          ;;
        aarch64|arm64)
          archives=(
            "clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu.tar.xz"
            "clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu-ubuntu-22.04.tar.xz"
            "clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu-ubuntu-20.04.tar.xz"
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
          archives=(
            "clang+llvm-${LLVM_VERSION}-arm64-apple-darwin23.0.tar.xz"
            "clang+llvm-${LLVM_VERSION}-arm64-apple-darwin22.0.tar.xz"
          )
          ;;
        x86_64)
          archives=(
            "clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin22.0.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin21.0.tar.xz"
            "clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin20.0.tar.xz"
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

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

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

echo "LLVM installed to ${PREFIX}" >&2
