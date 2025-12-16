#!/usr/bin/env bash
set -euo pipefail

# Build QuickScript for multiple targets.
# Usage: ./build_all.sh
# Override targets with: TARGETS="aarch64-apple-darwin x86_64-unknown-linux-gnu" ./build_all.sh

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="${ROOT}/dist"
mkdir -p "${DIST}"

TARGETS="${TARGETS:-aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-pc-windows-gnu}"

label_for_target() {
    case "$1" in
        aarch64-apple-darwin) echo "quick-darwin-arm64"; echo "" ;;
        x86_64-apple-darwin)  echo "quick-darwin-x86_64"; echo "" ;;
        aarch64-unknown-linux-gnu) echo "quick-linux-arm64"; echo "" ;;
        x86_64-unknown-linux-gnu)  echo "quick-linux-x86_64"; echo "" ;;
        x86_64-pc-windows-gnu)     echo "quick-windows-x86_64"; echo ".exe" ;;
        *) echo "unsupported"; echo "" ;;
    esac
}

build_target() {
    local target="$1"
    local label
    local ext

    # split return from label_for_target (label then ext)
    read -r label <<<"$(label_for_target "$target")"
    read -r ext <<<"$(label_for_target "$target" | tail -n 1)"

    if [[ "$label" == "unsupported" ]]; then
        echo "Skipping unsupported target: $target"
        return
    fi

    echo "== Building ${target}"

    if ! rustup target list | grep -q "^${target} (installed)"; then
        echo "Adding target ${target}..."
        if ! rustup target add "${target}"; then
            echo "Failed to add target ${target}, skipping."
            return
        fi
    fi

    if ! cargo build --release --target "${target}"; then
        echo "Build failed for ${target}, skipping copy."
        return
    fi

    local bin="${ROOT}/target/${target}/release/quick${ext}"
    if [[ ! -f "${bin}" ]]; then
        echo "Binary not found at ${bin}, skipping."
        return
    fi

    local dest="${DIST}/${label}${ext}"
    cp "${bin}" "${dest}"
    echo "Copied to ${dest}"
}

for tgt in ${TARGETS}; do
    build_target "${tgt}"
done

echo "All done. Artifacts in ${DIST}"
