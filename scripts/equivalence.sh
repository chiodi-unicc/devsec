#!/usr/bin/env bash
# Proves devsec's orchestration does not change tool results: run each tool directly in
# a clean repo, then via `devsec scan`, and compare result sets (ignoring timings/ids).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(cd "$(mktemp -d)" && pwd -P)"; trap 'rm -rf "$work"' EXIT
repo="$work/repo"; direct="$work/direct"; mkdir -p "$direct"
"$root/scripts/make-example.sh" "$repo"

# Direct runs first, on the pristine repo (trivy and syft don't read .gitignore,
# so they would otherwise also walk into .devsec/).
cd "$repo"
semgrep scan --config p/default --config p/secrets --metrics=off --quiet --json-output="$direct/semgrep.json" . >/dev/null
trivy fs --quiet --scanners secret --format json --output "$direct/trivy-secrets.json" .
syft scan dir:. --quiet --output cyclonedx-json="$direct/sbom.cdx.json"
trivy sbom --quiet --format json --output "$direct/trivy-sca.json" "$direct/sbom.cdx.json"

node "$root/apps/cli/dist/main.js" scan -C "$repo" --quiet >/dev/null || true
run="$repo/.devsec/latest"

status=0
check() { # name, jq filter, direct file, devsec file
  if diff <(jq -S "$2" "$3") <(jq -S "$2" "$4") >/dev/null; then echo "✓ $1 identical"
  else echo "✗ $1 differs"; diff <(jq -S "$2" "$3") <(jq -S "$2" "$4") || true; status=1; fi
}
check semgrep '[.results[] | {check_id, path, start, end, extra: (.extra | del(.metadata))}] | sort_by(.check_id, .path, .start.offset)' "$direct/semgrep.json" "$run/raw/semgrep.json"
check trivy-secrets '[.Results[] | {Target, Secrets}] | sort_by(.Target)' "$direct/trivy-secrets.json" "$run/raw/trivy-secrets.json"
check syft-sbom '[.components[] | {name, version, purl, type}] | sort_by(.name)' "$direct/sbom.cdx.json" "$run/sbom.cdx.json"
check trivy-sca '[.Results[].Vulnerabilities[] | {VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity}] | sort_by(.VulnerabilityID, .PkgName)' "$direct/trivy-sca.json" "$run/raw/trivy-sca.json"
exit $status
