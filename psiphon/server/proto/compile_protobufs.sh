#!/usr/bin/env bash
set -euo pipefail

fatal () { printf 'FATAL: %s\n' "${*}" >&2; exit 1; }

_src="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd -P)"
cd "${_src}" || fatal "failed to change to script source directory: ${_src}"

for cmd in "protoc" "protoc-gen-go"; do
  command -v "${cmd}" &> /dev/null || fatal "required command not found: ${cmd}"
done

find . -mindepth 1 -maxdepth 1 -type d -name 'ca.psiphon.*' | sed -e 's|^\./||' | while IFS= read -r src; do
  pkg="${src##*.}"

  mkdir -p "../pb/${pkg}" || fatal "failed to create compiled protobuf directory: ../pb/${pkg}"
  protoc --go_out="../pb/${pkg}/" --go_opt="module=github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/pb/${pkg}" "${src}/"*.proto
done
