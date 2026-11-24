#!/usr/bin/env bash
# Record real tool output for core's projection tests.
# Runs each tool exactly as devsec does: cwd = snapshot root, target ".".
# Secret-shaped strings are replaced afterwards so fixtures never contain them.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/packages/core/src/tools/__fixtures__"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$root/scripts/make-example.sh" "$work/repo"
cd "$work/repo"
mkdir -p "$out"

syft scan dir:. -q -o cyclonedx-json="$out/syft.cdx.json"
semgrep scan --config p/default --config p/secrets --metrics=off --quiet --no-git-ignore \
  --json-output="$out/semgrep.json" --sarif-output="$out/semgrep.sarif" . >/dev/null
trivy fs -q --scanners secret --format json --output "$out/trivy-secrets.json" .
trivy convert -q --format sarif --output "$out/trivy-secrets.sarif" "$out/trivy-secrets.json"
trivy sbom -q --format json --output "$out/trivy-sca.json" "$out/syft.cdx.json"
trivy convert -q --format sarif --output "$out/trivy-sca.sarif" "$out/trivy-sca.json"

# Redact the generated secrets (they're random but secret-shaped).
secrets=$(grep -oE '"[^"]+"' config.js | tr -d '"')
for s in $secrets; do
  for f in "$out"/*; do sed -i.bak "s|$s|REDACTED|g" "$f" && rm "$f.bak"; done
done
echo "fixtures written to $out"
