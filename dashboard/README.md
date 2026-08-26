# rch fleet dashboard

A static, password-gated monitoring console for an [`rch`](../) build fleet.

It answers the two questions that matter when you run distributed compilation,
and that every other surface answers badly:

1. **Are my dev machines actually offloading?** — or has one quietly started
   compiling everything on itself while still reporting a healthy worker pool?
2. **Is the worker pool healthy?** — slots really in use (not the configured
   ceiling), disk headroom, CPU load, pressure state, circuit breakers.

It deploys as plain static files to Vercel, GitHub Pages, or any static host.
There is no server, no database, and no API key — the whole thing is one
encrypted JSON blob plus a React app that decrypts it in your browser.

```
  dev machines ──ssh──▶ tools/snapshot.mjs ──AES-256-GCM──▶ fleet.enc.json
  (boxes running rch)                                             │
                                                          static hosting
                                                                  │
                                       browser: PBKDF2(passphrase) ─▶ decrypt ─▶ UI
```

---

## Why this exists

`rch` distributes compilation from **dev machines** (dispatchers, which run
`rchd` and decide where a build goes) to a **worker pool**. The dangerous
failure mode is not a worker dying loudly — it is a dev machine that *stops
offloading and does not tell you*.

`rch` fails open by design: if no worker is admissible, the build runs locally
and succeeds. Your build still works, so nothing alarms. Meanwhile `rch queue`
reports a full pool of healthy workers, every probe passes, and the whole
cluster sits idle while one box melts.

One concrete way this happens: `rchd` derates each worker's slot count from live
RAM/disk telemetry, independently on every dispatcher. A build asks for
`compilation.build_slots` slots. If derating pushes the *whole* pool below that
number, every worker becomes inadmissible at once and every build silently goes
local. `rch workers list` will not show it — that command prints the
**configured** slot ceiling, not the derated reality.

So this dashboard leads with **offload posture and the remote-vs-local build
split**, and shows the **derated** slot numbers rather than the configured ones.

---

## Security model

The snapshot contains hostnames, IP addresses and hardware inventory. If you
publish it anywhere reachable, that inventory is exposed. So it is never written
in the clear.

- Payload is **AES-256-GCM** ciphertext.
- Key is **PBKDF2-HMAC-SHA256, 600,000 iterations**, derived from your passphrase.
- Decryption happens **entirely in the browser**. The passphrase is never sent
  anywhere and never stored.
- "Stay unlocked" stores the **derived key**, not the passphrase, in a cookie for
  60 days (`SameSite=Strict`, `Secure`, scoped to the app's base path).

This is real confidentiality, not a client-side `if (password === "...")` check
that anyone can bypass by reading the JavaScript.

### The honest limits

**Client-side crypto gives confidentiality, not authorization.** If the URL is
reachable, anyone can download the ciphertext and attack it offline, forever, at
their leisure. Its safety rests entirely on passphrase entropy. Generate one
properly:

```sh
head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '='   # 256 bits
```

A dictionary phrase will eventually fall. You cannot un-publish a blob someone
already copied, and you cannot rotate a passphrase retroactively.

**Prefer a host that also gates access.** Confidentiality and access control
compose well:

| Layer | Stops |
|---|---|
| Host access control (Vercel Deployment Protection, private repo Pages, VPN) | anonymous download of the ciphertext |
| AES-256-GCM + PBKDF2 | reading it without the passphrase |

With both, an attacker needs to defeat your host's auth *before* they can even
begin an offline attack. Vercel enables Deployment Protection on new projects by
default — leaving it on is the recommended configuration.

**Never commit a snapshot.** `public/data/` and `*.enc.json` are git-ignored.
Committing ciphertext pins its salt into git history forever, so a future
passphrase compromise retroactively exposes every snapshot you ever committed.

---

## Quick start

```sh
cd dashboard
npm install

cp .env.example .env      # then fill it in — .env is git-ignored
$EDITOR .env

npm run snapshot -- --dispatchers builder-a,builder-b,local
npm run dev               # http://localhost:5173
```

`.env` holds your real host list so it never lands in source:

```sh
RCH_DASH_PASSPHRASE='<32+ random chars>'
RCH_DASH_DISPATCHERS='builder-a,builder-b,local'
RCH_DASH_LABEL='my rch fleet'
```

Quote every value. `set -a; . ./.env` word-splits unquoted values and will
happily execute the tail of one as a command.

`--dispatchers` takes **ssh targets that run `rch`** — your dev machines, not
your workers. Workers are discovered automatically from each dev machine's view
of the pool. Use `local` for the machine you collect from, so it monitors itself
too.

### Storing the passphrase in Vault

If you run HashiCorp Vault, keep the canonical copy there and let `.env` be a
convenience cache:

```sh
# store (stdin, so the secret never appears in ps/argv)
printf '{"passphrase":"%s"}' "$PW" \
  | vault kv put secret/rch-fleet-dashboard -

# read back
vault kv get -field=passphrase secret/rch-fleet-dashboard
```

`scripts/deploy-vercel.sh` falls back to Vault automatically when `.env` has no
passphrase, so a scheduled deploy works on a box with no secrets on disk.

---

## Deploying

### Vercel (recommended)

```sh
scripts/deploy-vercel.sh                # collect + build + deploy to production
scripts/deploy-vercel.sh --no-snapshot  # redeploy existing data
scripts/deploy-vercel.sh --preview      # preview deployment
```

The script deploys **prebuilt output** (Build Output API v3), so Vercel never
runs a build, never clones the repo, and never sees `.env`. Before uploading it
refuses to continue if:

- the data file is not an encrypted envelope,
- anything other than the ciphertext appears under `dist/data/`,
- the passphrase appears anywhere inside `dist/`.

It also sets `Content-Security-Policy`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, HSTS, and `X-Robots-Tag: noindex`, with
`Cache-Control: no-store` on the snapshot so a CDN edge can never serve a stale
fleet view that looks live.

Set `RCH_DASH_VERCEL_PROJECT` to control the project name.

### GitHub Pages

```sh
scripts/deploy.sh --repo git@github.com:<you>/<private-dash>.git
```

Prefer a **private** repo's Pages site. The script refuses to target a public
repo without a typed confirmation.

### Neither is a CI job — on purpose

Both scripts are local. A monitoring dashboard that silently stops refreshing is
worse than no dashboard, and scheduled CI is exactly the thing that stops
quietly. Run it from cron on a box you control:

```sh
*/10 * * * * cd /path/to/dashboard && ./scripts/deploy-vercel.sh >/dev/null 2>&1
```

Each run appends to a rolling aggregate history (`.snapshot-history.json`, kept
outside `public/` so it is never published) which drives the trend sparklines.

---

## What it shows

### Dev machines

Per box running `rch`:

| Field | Meaning |
|---|---|
| `offloading` / `idle` / `degraded` / `local-only` / `unreachable` | derived posture |
| offload bar | recent builds that went remote vs local |
| slots | free / total across the pool *as this machine sees it* |
| daemon | `rchd` version, uptime, healthy worker count |
| remediation hints | `rch`'s own per-worker advice |
| recent builds | each build's local-vs-remote outcome, worker, duration |

`local-only` is the alarm: builds are running on the dev box instead of the pool.

### Workers

| Field | Meaning |
|---|---|
| slots | **derated** used / total, per `rch status` |
| cpu | 1-minute load against core count |
| disk | free space and used percentage |
| SpeedScore | `rch`'s own worker ranking |
| pressure | state + reason code (disk ratio, disk IO, memory) |
| circuit | breaker state, consecutive failures, probe history strip |

Worker health, worst first:

| Status | Meaning |
|---|---|
| `disabled` | disabled in `workers.toml` |
| `offline` | circuit open, worker down, or not seen for over an hour |
| `critical` | pressure critical, or disk ≥ 95% |
| `warn` | pressure warning, disk ≥ 88%, load ≥ 2× cores, recent failures, half-open circuit |
| `busy` | slots in use |
| `healthy` | none of the above |

"We cannot see it" outranks a stale disk reading, because reachability is the
more actionable fact. Disk outranks load: a full disk takes a worker down hard,
while high load is usually just work happening.

The snapshot's age is shown at all times and turns amber past 15 minutes, red
past an hour.

---

## Data sources

All from documented `--json` CLI contracts, so nothing depends on scraping
human-readable output:

| Source | Provides |
|---|---|
| `rch status --json` | posture, daemon, derated slots, pressure, circuit state, recent builds, remote/local counts, remediation hints |
| `rch workers capabilities --json` | cores, load average, toolchain versions |
| `:9100/metrics` | probe latency, last-seen timestamps |

Facts are unioned across dev machines, so one unreachable box cannot blank the
fleet view. Each worker records which machines can see it, and its slot counts
per machine — because `rchd` derates independently on each.

---

## Testing

```sh
npm run build
npm run serve:dist &
RCH_DASH_PASSPHRASE='...' npm run test:e2e
```

Drives real Chromium against a real encrypted snapshot: gate, wrong-vs-right
passphrase, rendering, drawers, filtering, theme, cookie session, lock, mobile
overflow, console errors. This test is what caught a slot double-count that
reported 198 build slots for an 80-slot fleet.

## Layout

```
dashboard/
  tools/snapshot.mjs        collector + encryptor (Node, no dependencies)
  scripts/deploy-vercel.sh  build + prebuilt deploy to Vercel
  scripts/deploy.sh         build + deploy to GitHub Pages
  tests/e2e.mjs             browser end-to-end smoke test
  src/crypto.ts             PBKDF2 + AES-GCM + cookie session
  src/derive.ts             health + posture classification
  src/App.tsx               layout, filtering, sorting
  src/components/           Gate, WorkerCard/Drawer, DevMachineCard/Drawer, Sparkline
  src/styles.css            design tokens (dark + light)
```

## Base path

Vercel serves at the root, which is the default for `deploy-vercel.sh`
(`RCH_DASH_BASE=/`). GitHub Pages project sites serve from `/<repo>/`:

```sh
RCH_DASH_BASE=/my-repo/ npm run build
```
