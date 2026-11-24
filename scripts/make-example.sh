#!/usr/bin/env bash
# Copy examples/vulnerable into a fresh git repo at $1, adding random fake secrets.
set -euo pipefail
dest="${1:?usage: make-example.sh <dest-dir>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
rand() { LC_ALL=C tr -dc "$1" </dev/urandom | head -c "$2" || true; }

rm -rf "$dest" && mkdir -p "$dest"
cp "$root"/examples/vulnerable/{app.js,package.json,package-lock.json} "$dest"/
cat > "$dest/config.js" <<JS
const AWS_ACCESS_KEY_ID = "AKIA$(rand 'A-Z2-7' 16)";
const AWS_SECRET_ACCESS_KEY = "$(rand 'A-Za-z0-9' 40)";
const GITHUB_TOKEN = "ghp_$(rand 'A-Za-z0-9' 36)";
module.exports = { AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN };
JS
git -C "$dest" init -q
git -C "$dest" add -A
git -C "$dest" -c user.name=devsec -c user.email=devsec@localhost commit -qm "vulnerable example"
