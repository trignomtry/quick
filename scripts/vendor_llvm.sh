#!/usr/bin/env bash
set -euo pipefail

LLVM_TAG=${LLVM_TAG:-llvmorg-18.1.8}
LLVM_VERSION=${LLVM_TAG#llvmorg-}
PREFIX=${LLVM_PREFIX:-$(pwd)/llvm/install}

os=$(uname -s)
arch=$(uname -m)

case "${os}" in
  Linux)
    case "${arch}" in
      x86_64|amd64)
        archive="clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-22.04.tar.xz"
        ;;
      aarch64|arm64)
        archive="clang+llvm-${LLVM_VERSION}-aarch64-linux-gnu.tar.xz"
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
        archive="clang+llvm-${LLVM_VERSION}-arm64-apple-darwin23.0.tar.xz"
        ;;
      x86_64)
        archive="clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin20.0.tar.xz"
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

url="https://github.com/llvm/llvm-project/releases/download/${LLVM_TAG}/${archive}"
tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

echo "Downloading LLVM (${LLVM_VERSION}) from ${url}" >&2
if ! curl -fsSL "${url}" -o "${tmpdir}/${archive}"; then
  echo "Failed to download ${url}" >&2
  exit 1
fi

echo "Extracting ${archive}" >&2
if ! tar -xJf "${tmpdir}/${archive}" -C "${tmpdir}"; then
  echo "Failed to extract ${archive}" >&2
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
