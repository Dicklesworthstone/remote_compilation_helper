# rch fleet dashboard

A static, password-gated monitoring console for an `rch` build fleet: slot
utilisation, which workers are busy, disk headroom, CPU load, SpeedScores,
circuit state, toolchain inventory, and per-dispatcher queue health.

It deploys to GitHub Pages as plain static files. There is no server, no
database and no API key — the whole thing is one encrypted JSON blob plus a
React app that decrypts it in your browser.

```
  rch dispatchers  ──ssh──▶  tools/snapshot.mjs  ──AES-256-GCM──▶  fleet.enc.json
                                                                        │
                                                          GitHub Pages (static)
                                                                        │
                                            browser: PBKDF2(passphrase) ─▶ decrypt ─▶ UI
```

## Why the payload is encrypted

`remote_compilation_helper` is a **public** repository, and a fleet snapshot
contains hostnames, IP addresses and hardware inventory. Publishing that in
clear text would hand over the topology of the entire build fleet.

So the snapshot is **AES-256-GCM ciphertext**, keyed by **PBKDF2-HMAC-SHA256**
over your passphrase at **600,000 iterations**. Without the passphrase the file
is indistinguishable from random bytes. This is real protection, not a
client-side `if (password === "...")` check that anyone can bypass by reading
the JavaScript.

**Two honest limits:**

1. **Client-side crypto cannot enforce authorization — only confidentiality.**
   Anyone can download the ciphertext. Its safety rests entirely on passphrase
   entropy. Use something long and random (24+ characters). A dictionary phrase
   will eventually fall to an offline attack, and you cannot un-publish a blob
   someone already copied.
2. **Prefer a private repo.** The deploy script defaults to your `origin` and
   will refuse to publish to the public repo without an explicit typed
   confirmation. Pointing it at a private repo's Pages site removes the offline
   attack surface almost entirely:
   ```sh
   scripts/deploy.sh --repo git@github.com:<you>/<private-dash>.git
   ```

The session cookie stores the **derived key**, never the passphrase, for 60
days (`SameSite=Strict`, `Secure` on https).

## Quick start

```sh
cd dashboard
npm install

# 1. Collect + encrypt a snapshot (needs ssh access to the dispatchers)
export RCH_DASH_PASSPHRASE='<a long, random passphrase>'
npm run snapshot -- --dispatchers trj,css,csd,ts1,ts2 --label "my fleet"

# 2. Run it locally
npm run dev            # http://localhost:5173

# 3. Publish
scripts/deploy.sh --repo git@github.com:<you>/<private-dash>.git
```

## Refreshing the data

The dashboard shows a point-in-time snapshot and says how old it is, turning
the indicator amber past 15 minutes and red past an hour — a stale dashboard
that looks live is worse than no dashboard.

Re-run the collector on whatever cadence you want:

```sh
# cron, every 10 minutes
*/10 * * * * cd /path/to/dashboard && RCH_DASH_PASSPHRASE=... scripts/deploy.sh >/dev/null 2>&1
```

Pass `--history-from` to accumulate a rolling trend series across runs, which
turns on the "free slots over time" sparkline:

```sh
npm run snapshot -- --history-from public/data/fleet.plain.json
```

**This is deliberately not a GitHub Actions workflow.** This fleet's standing
rule is not to depend on Actions — budget blocks have silently killed scheduled
runs before, and a monitoring dashboard that quietly stops updating is a
liability. Run it from a machine you control.

## What the collector reads

All from documented `--json` CLI contracts, so it does not scrape
human-readable output:

| Source | Provides |
|---|---|
| `rch workers list --json` | id, host, user, slots, priority, tags |
| `rch workers capabilities --json` | cores, load average, disk free/total, toolchain versions |
| `rch queue --json` | aggregate slots, active/queued builds |
| `rch daemon status --json` | daemon liveness, uptime |
| `rch workers compare --json` | SpeedScore |
| `:9100/metrics` | circuit state, last-seen, probe latency |

Facts are unioned across dispatchers, so one unreachable box cannot blank the
fleet view; each worker records which dispatchers can see it.

## How health is decided

Derived in the browser (`src/derive.ts`), worst-first:

| Status | Meaning |
|---|---|
| `disabled` | `enabled = false` in `workers.toml` |
| `offline` | circuit breaker open, or not seen for over an hour |
| `critical` | disk ≥ 95% full |
| `warn` | disk ≥ 88%, load ≥ 2× cores, circuit half-open, or projects root unhealthy |
| `busy` | has active builds |
| `healthy` | none of the above |

"We cannot see it" outranks a stale disk reading, because reachability is the
more actionable fact. Disk outranks load: a full disk takes a worker down hard,
while high load is usually just work happening.

## Layout

```
dashboard/
  tools/snapshot.mjs      collector + encryptor (Node, no deps)
  scripts/deploy.sh       build + publish to Pages
  src/crypto.ts           PBKDF2 + AES-GCM + cookie session
  src/derive.ts           health classification, formatting
  src/App.tsx             layout, filtering, sorting
  src/components/         Gate, WorkerCard, WorkerDrawer, Sparkline
  src/styles.css          design tokens (dark + light)
```

`public/data/` is git-ignored: the snapshot belongs in the deployed artifact,
never in source history, where a future passphrase compromise would
retroactively expose every snapshot ever committed.

## Base path

GitHub Pages project sites serve from `/<repo>/`, which is the default. For a
user/organisation page or a custom domain:

```sh
RCH_DASH_BASE=/ npm run build
```
