#!/usr/bin/env bash
#
# Collect + encrypt the fleet snapshot and publish ONLY the ciphertext to
# Vercel Blob. No app deploy — this is the fast tick (every 2 minutes from
# launchd/cron), and `deploy-vercel.sh` is the slow one that ships code.
#
#   scripts/publish-snapshot.sh            # collect + upload
#   scripts/publish-snapshot.sh --no-collect  # upload the existing file
#
# Reads .env (RCH_DASH_PASSPHRASE / DISPATCHERS / LABEL / API_TOKEN) and
# .env.vercel (BLOB_READ_WRITE_TOKEN, from `vercel env pull .env.vercel`).
# Both are gitignored. The blob URL is stable
# (https://<store>.public.blob.vercel-storage.com/fleet.enc.json) and is what
# the app and /api/fleet fetch at runtime (RCH_DASH_DATA_URL).
#
# Why this is safe to publish: the file is AES-256-GCM ciphertext, the same
# bytes the static site already served. The blob store is public because the
# ciphertext is; the passphrase is the only secret and it never leaves your
# machines. --cache-control-max-age 60 keeps the CDN from serving a stale
# fleet view for longer than a minute.
#
set -euo pipefail
cd "$(dirname "$0")/.."

DO_COLLECT=1
while [ $# -gt 0 ]; do
  case "$1" in
    --no-collect) DO_COLLECT=0; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ -f .env ]; then set -a; . ./.env; set +a; fi
if [ -f .env.vercel ]; then set -a; . ./.env.vercel; set +a; fi

if [ -z "${RCH_DASH_PASSPHRASE:-}" ]; then
  echo "RCH_DASH_PASSPHRASE unavailable (.env)." >&2
  exit 2
fi
if [ -z "${BLOB_READ_WRITE_TOKEN:-}" ]; then
  echo "BLOB_READ_WRITE_TOKEN unavailable: run \`vercel env pull .env.vercel --environment production --yes\` in dashboard/." >&2
  exit 2
fi

OUT=public/data/fleet.enc.json
if [ "$DO_COLLECT" = "1" ]; then
  node tools/snapshot.mjs \
    --dispatchers "${RCH_DASH_DISPATCHERS:-local}" \
    --label "${RCH_DASH_LABEL:-rch fleet}" \
    --out "$OUT"
fi

# Never publish anything that is not an encrypted envelope.
if ! grep -q '"ciphertext"' "$OUT"; then
  echo "REFUSING TO PUBLISH: $OUT is not an encrypted envelope." >&2
  exit 1
fi

START=$(date +%s)
URL=$(vercel blob put "$OUT" \
  --pathname fleet.enc.json \
  --access public \
  --allow-overwrite \
  --cache-control-max-age 60 \
  --content-type application/json \
  --rw-token "$BLOB_READ_WRITE_TOKEN" 2>&1 | grep -o 'https://[^ ]*fleet\.enc\.json' | head -1)
if [ -z "$URL" ]; then
  echo "blob upload failed" >&2
  exit 1
fi
if [ -n "${RCH_DASH_DATA_URL:-}" ] && [ "$URL" != "$RCH_DASH_DATA_URL" ]; then
  echo "note: blob URL $URL differs from RCH_DASH_DATA_URL in .env ($RCH_DASH_DATA_URL) — update .env and the Vercel project env" >&2
fi
echo "==> published $URL in $(( $(date +%s) - START ))s at $(date -u +%FT%TZ)"
