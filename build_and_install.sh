#!/usr/bin/env bash
set -euo pipefail

TARGET=x86_64-pc-windows-gnu
SRC="target/${TARGET}/release/DirectorySpider.exe"
DST="precompiled/Win64_DirectorySpider.exe"

cd "$(dirname "$0")"

cargo build --release --target "${TARGET}"

mkdir -p "$(dirname "${DST}")"
cp "${SRC}" "${DST}"

echo "Copied ${SRC} -> ${DST}"
