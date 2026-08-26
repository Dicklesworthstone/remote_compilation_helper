#!/usr/bin/env bash
#
# Refresh the fleet snapshot and publish the dashboard to Vercel.
#
#   scripts/deploy-vercel.sh                 # collect + build + deploy to prod
#   scripts/deploy-vercel.sh --no-snapshot   # redeploy the existing snapshot
#   scripts/deploy-vercel.sh --preview       # deploy a preview instead of prod
#
# Reads .env (gitignored) for RCH_DASH_PASSPHRASE / DISPATCHERS / LABEL.
# The canonical passphrase lives in Vault:
#   vault kv get -field=passphrase secret/rch-fleet-dashboard
#
# Deliberately a LOCAL script, not a CI job: this fleet does not rely on GitHub
# Actions, and a monitoring dashboard that silently stops refreshing is worse
# than no dashboard at all. Run it from cron on a box you control.
#
set -euo pipefail
cd "$(dirname "$0")/.."

DO_SNAPSHOT=1
TARGET_PROD=1
while [ $# -gt 0 ]; do
  case "$1" in
    --no-snapshot) DO_SNAPSHOT=0; shift ;;
    --preview) TARGET_PROD=0; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Load .env if present; values are quoted there so `set -a` cannot word-split
# one into a stray command.
if [ -f .env ]; then set -a; . ./.env; set +a; fi

# Fall back to Vault so the script works on a box without a local .env.
if [ -z "${RCH_DASH_PASSPHRASE:-}" ]; then
  echo "==> no RCH_DASH_PASSPHRASE in env/.env; trying Vault"
  RCH_DASH_PASSPHRASE=$(
    VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT="$HOME/.vault-ca.crt" \
      vault kv get -field=passphrase secret/rch-fleet-dashboard 2>/dev/null || true
  )
  export RCH_DASH_PASSPHRASE
fi
if [ -z "${RCH_DASH_PASSPHRASE:-}" ]; then
  echo "RCH_DASH_PASSPHRASE unavailable (not in .env, not in Vault)." >&2
  exit 2
fi

DISPATCHERS="${RCH_DASH_DISPATCHERS:-local}"
LABEL="${RCH_DASH_LABEL:-rch fleet}"

if [ "$DO_SNAPSHOT" = "1" ]; then
  echo "==> collecting from: $DISPATCHERS"
  node tools/snapshot.mjs --dispatchers "$DISPATCHERS" --label "$LABEL" \
       --out public/data/fleet.enc.json
fi

if [ ! -f public/data/fleet.enc.json ]; then
  echo "no snapshot at public/data/fleet.enc.json" >&2
  exit 1
fi

echo "==> building (base=/ for Vercel root hosting)"
RCH_DASH_BASE=/ npm run build

echo "==> bundling /api/fleet (LLM endpoint)"
# The snapshot is imported INTO the bundle, so the function needs no filesystem
# or network access at runtime. Nothing secret is baked in — only the same
# ciphertext the browser already downloads; it decrypts with the CALLER's key.
npm run build:api

# --- refuse to publish anything unencrypted -------------------------------
if ! grep -q '"ciphertext"' dist/data/fleet.enc.json; then
  echo "REFUSING TO DEPLOY: dist/data/fleet.enc.json is not an encrypted envelope." >&2
  exit 1
fi
# Vite copies public/ verbatim, so anything that lands there ships. Only the
# ciphertext is allowed out.
EXTRA=$(find dist/data -type f ! -name 'fleet.enc.json' | head -5)
if [ -n "$EXTRA" ]; then
  echo "REFUSING TO DEPLOY: unexpected files under dist/data:" >&2
  echo "$EXTRA" >&2
  exit 1
fi
PREFIX=$(printf '%s' "$RCH_DASH_PASSPHRASE" | cut -c1-12)
if grep -rq "$PREFIX" dist 2>/dev/null; then
  echo "REFUSING TO DEPLOY: the passphrase appears inside dist/." >&2
  exit 1
fi

# --- assemble a Build Output API v3 bundle ---------------------------------
# Deploying prebuilt output rather than sources keeps the passphrase and .env
# off Vercel entirely — Vercel never runs a build and never sees the repo.
STAMP=$(date -u +%Y%m%d%H%M%S)
PROJECT="${RCH_DASH_VERCEL_PROJECT:-rch-fleet}"
OUT="${TMPDIR:-/tmp}/$PROJECT-$STAMP/$PROJECT"
mkdir -p "$OUT/.vercel/output/static"
cp -R dist/. "$OUT/.vercel/output/static/"
node -e '
const fs = require("fs");
const sec = {
  "x-robots-tag": "noindex, nofollow, noarchive, nosnippet",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy":
    "default-src '"'"'self'"'"'; script-src '"'"'self'"'"'; style-src '"'"'self'"'"' '"'"'unsafe-inline'"'"'; " +
    "img-src '"'"'self'"'"' data:; connect-src '"'"'self'"'"'; font-src '"'"'self'"'"'; object-src '"'"'none'"'"'; " +
    "base-uri '"'"'none'"'"'; form-action '"'"'none'"'"'; frame-ancestors '"'"'none'"'"'",
};
const cfg = { version: 3, routes: [
  { src: "^/data/(.*)$",   headers: { ...sec, "cache-control": "no-store, max-age=0, must-revalidate" }, continue: true },
  { src: "^/assets/(.*)$", headers: { ...sec, "cache-control": "public, max-age=31536000, immutable" },  continue: true },
  { src: "^/(.*)$",        headers: sec, continue: true },
  { handle: "filesystem" },
  // /api/fleet is a function, not a static file, so it resolves only after
  // the filesystem pass falls through.
  { src: "^/api/fleet/?$", dest: "/api/fleet" },
]};
fs.writeFileSync(process.argv[1], JSON.stringify(cfg, null, 2));
' "$OUT/.vercel/output/config.json"

# --- serverless function: GET /api/fleet -----------------------------------
FN="$OUT/.vercel/output/functions/api/fleet.func"
mkdir -p "$FN"
cp .vercel-fn/index.mjs "$FN/index.mjs"
printf '%s\n' \
  '{' \
  '  "runtime": "nodejs22.x",' \
  '  "handler": "index.mjs",' \
  '  "launcherType": "Nodejs",' \
  '  "shouldAddHelpers": true' \
  '}' > "$FN/.vc-config.json"

echo "==> deploying prebuilt bundle to Vercel"
cd "$OUT"
if [ "$TARGET_PROD" = "1" ]; then
  vercel deploy --prebuilt --prod --yes
  echo "==> production: https://$PROJECT.vercel.app"
else
  vercel deploy --prebuilt --yes
fi
