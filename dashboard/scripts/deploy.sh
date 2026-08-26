#!/usr/bin/env bash
#
# Build the fleet dashboard and publish it to GitHub Pages.
#
# Deliberately a LOCAL script, not a GitHub Actions workflow: this fleet's
# operating rule is "never rely on GitHub Actions" (budget blocks have silently
# killed scheduled runs before), and a dashboard that stops refreshing without
# telling you is worse than no dashboard.
#
# Usage:
#   RCH_DASH_PASSPHRASE='...' scripts/deploy.sh                  # refresh snapshot + deploy
#   RCH_DASH_PASSPHRASE='...' scripts/deploy.sh --no-snapshot    # deploy current data as-is
#   RCH_DASH_PASSPHRASE='...' scripts/deploy.sh --repo git@github.com:me/private-dash.git
#
set -euo pipefail

cd "$(dirname "$0")/.."

DISPATCHERS="${RCH_DASH_DISPATCHERS:-local}"
LABEL="${RCH_DASH_LABEL:-rch fleet}"
BRANCH="${RCH_DASH_BRANCH:-gh-pages}"
TARGET_REPO=""
DO_SNAPSHOT=1

while [ $# -gt 0 ]; do
  case "$1" in
    --no-snapshot) DO_SNAPSHOT=0; shift ;;
    --repo) TARGET_REPO="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --dispatchers) DISPATCHERS="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ -z "${RCH_DASH_PASSPHRASE:-}" ]; then
  echo "RCH_DASH_PASSPHRASE is not set." >&2
  exit 2
fi

ORIGIN_URL="$(git -C .. remote get-url origin 2>/dev/null || echo '')"
if [ -z "$TARGET_REPO" ]; then
  TARGET_REPO="$ORIGIN_URL"
  case "$ORIGIN_URL" in
    *remote_compilation_helper*)
      cat >&2 <<'WARN'
┌──────────────────────────────────────────────────────────────────────────┐
│ WARNING: the default target is the PUBLIC remote_compilation_helper repo.│
│                                                                          │
│ The snapshot is AES-256-GCM encrypted, so its contents stay unreadable   │
│ without the passphrase — but the ciphertext itself becomes world-        │
│ downloadable and permanent. Anyone can grab it now and brute-force it    │
│ later, at their leisure, against a passphrase you cannot rotate          │
│ retroactively.                                                           │
│                                                                          │
│ Strongly prefer a PRIVATE repo's Pages site:                             │
│   scripts/deploy.sh --repo git@github.com:<you>/<private-dash>.git       │
│                                                                          │
│ If you continue, use a long, high-entropy passphrase (>= 24 chars).      │
└──────────────────────────────────────────────────────────────────────────┘
WARN
      printf 'Type PUBLISH-TO-PUBLIC-REPO to continue: ' >&2
      read -r confirm
      [ "$confirm" = "PUBLISH-TO-PUBLIC-REPO" ] || { echo "aborted." >&2; exit 1; }
      ;;
  esac
fi

if [ "$DO_SNAPSHOT" = "1" ]; then
  echo "==> collecting snapshot from: $DISPATCHERS"
  node tools/snapshot.mjs --dispatchers "$DISPATCHERS" --label "$LABEL" \
       --out public/data/fleet.enc.json
fi

if [ ! -f public/data/fleet.enc.json ]; then
  echo "no snapshot at public/data/fleet.enc.json — run without --no-snapshot" >&2
  exit 1
fi

echo "==> building"
npm run build

# Vite copies public/ into dist/, so the encrypted snapshot ships with the app.
if [ ! -f dist/data/fleet.enc.json ]; then
  echo "build did not include dist/data/fleet.enc.json" >&2
  exit 1
fi

# Refuse to publish a plaintext snapshot, whatever else went wrong.
if ! grep -q '"ciphertext"' dist/data/fleet.enc.json; then
  echo "REFUSING TO DEPLOY: dist/data/fleet.enc.json is not an encrypted envelope." >&2
  exit 1
fi

echo "==> publishing dist/ to $BRANCH on $TARGET_REPO"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp -R dist/. "$WORK/"
touch "$WORK/.nojekyll"   # keep Pages from eating /assets/_* paths

git -C "$WORK" init -q
git -C "$WORK" checkout -q -b "$BRANCH"
git -C "$WORK" add -A
# Use whatever identity git already has; the deploy branch is disposable.
git -C "$WORK" -c user.name="${GIT_AUTHOR_NAME:-fleet-dashboard}" \
    -c user.email="${GIT_AUTHOR_EMAIL:-fleet-dashboard@localhost}" \
    commit -q -m "deploy fleet dashboard $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git -C "$WORK" push -q --force "$TARGET_REPO" "$BRANCH"

echo "==> done"
echo "    Enable Pages for branch '$BRANCH' (root) if you have not already."
