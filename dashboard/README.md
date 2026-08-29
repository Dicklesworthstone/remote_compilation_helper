# rch fleet dashboard

A static, password-gated monitoring console for an [`rch`](../) build fleet.

It answers the two questions that matter when you run distributed compilation,
and that every other surface answers badly:

1. **Are my dev machines actually offloading?** — or has one quietly started
   compiling everything on itself while still reporting a healthy worker pool?
2. **Is the worker pool healthy?** — slots really in use (not the configured
   ceiling), disk headroom, CPU load, pressure state, circuit breakers.

It deploys as static files to Vercel, GitHub Pages, or any static host: one
encrypted JSON blob plus a React app that decrypts it in your browser. There is
no database and no stored credential. The optional `/api/fleet` endpoint adds a
single stateless function for LLM/agent consumers — it holds no secret either
(see below).

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
# `name` = probe over ssh; `name=tailscale-ip:9101` = ask rchd's tailnet API
# (fast; see "How machines are collected" below)
RCH_DASH_DISPATCHERS='builder-a=100.64.1.2:9101,builder-b=100.64.1.3:9101,local=100.64.1.1:9101'
RCH_DASH_API_TOKEN='<the [api] token every rchd was configured with>'
RCH_DASH_LABEL='my rch fleet'
# after the blob store exists (see "Two ticks" below):
RCH_DASH_DATA_URL='https://<store>.public.blob.vercel-storage.com/fleet.enc.json'
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

### Two ticks: publish the snapshot (fast), deploy the app (slow)

Freshness and code ship on different schedules:

| Tick | Script | What it does | Cadence |
|---|---|---|---|
| **publish** | `scripts/publish-snapshot.sh` | collect (1–3 s over the tailnet API), encrypt, upload the ciphertext to **Vercel Blob**. No deploy. | every **120 s** |
| **deploy** | `scripts/deploy-vercel.sh` | build the app + `/api/fleet` function and deploy them (with a bundled fallback snapshot) | hourly, or when code changed |

The app and `/api/fleet` fetch the blob at runtime (`RCH_DASH_DATA_URL`; the
blob's CDN cache is 60 s), so a change on the fleet is visible within about
three minutes, and a deploy is no longer what makes data fresh. If the blob is
unreachable both fall back to the deploy-time copy **and say so** (a banner in
the app; `X-Rch-Snapshot-Source: bundled-fallback` on the endpoint).

One-time setup for the blob (needs a Vercel Blob store connected to the project):

```sh
vercel link --yes --project rch-fleet
vercel blob create-store rch-fleet-blob --access public \
  --environment production --environment preview --environment development --yes
vercel env pull .env.vercel --environment production --yes     # BLOB_READ_WRITE_TOKEN
scripts/publish-snapshot.sh                                    # prints the blob URL
echo "RCH_DASH_DATA_URL='https://<store>.public.blob.vercel-storage.com/fleet.enc.json'" >> .env
printf '%s' "$URL" | vercel env add RCH_DASH_DATA_URL production --yes   # the function reads it
scripts/deploy-vercel.sh                                       # bakes VITE_RCH_DASH_DATA_URL into the app
```

Neither tick is a CI job, on purpose: a monitoring dashboard that silently stops
refreshing is worse than no dashboard, and scheduled CI is exactly the thing
that stops quietly. Run both from a box you control.

**macOS (launchd)** — two checked-in agents, logging to
`~/Library/Logs/rch-dashboard-{publish,refresh}.log`:

```sh
for a in publish refresh; do
  sed "s#__DASHBOARD_DIR__#$PWD#g; s#__HOME__#$HOME#g" \
    ../packaging/launchd/com.local.rch-dashboard-$a.plist \
    > ~/Library/LaunchAgents/com.local.rch-dashboard-$a.plist
  launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.local.rch-dashboard-$a.plist
done
launchctl kickstart -k gui/$(id -u)/com.local.rch-dashboard-publish   # run one now
```

**Linux (cron)**:

```sh
*/2  * * * * cd /path/to/dashboard && ./scripts/publish-snapshot.sh >>"$HOME/rch-dashboard-publish.log" 2>&1
0    * * * * cd /path/to/dashboard && ./scripts/deploy-vercel.sh   >>"$HOME/rch-dashboard-refresh.log" 2>&1
```

Without a blob store the deploy tick alone still works (the app is then
static-only and every refresh is a deployment — Vercel's Hobby tier caps those
at 100/day, so keep that tick at 20 minutes or more).

Each publish appends to a rolling aggregate history (`.snapshot-history.json`,
kept outside `public/` so it is never published) which drives the trend
sparklines, and refreshes the ssh self-check cache (`.selfcheck-cache.json`,
same treatment).

### How machines are collected: the tailnet API, with ssh behind it

`rchd` can serve its full `/status` JSON over TCP on the tailnet (`[api]
bind = "tailscale"` in `config.toml`, bearer token — see
`docs/guides/configuration.md`). A dispatcher written as `name=100.x.y.z:9101`
in `RCH_DASH_DISPATCHERS` is asked over HTTP: four small GETs, no ssh key
exchange, sub-second, with `RCH_DASH_API_TOKEN` as the bearer. What the API
cannot answer — `rch doctor`, `rch shim status`, `rch hook status`, which are
dev-machine-local CLI checks — still comes over ssh, but only every 15 minutes
(`--selfcheck-max-age`), cached locally. A machine whose API does not answer
(old `rchd`, wrong token) falls back to the full ssh probe for that tick, and
its record says so (`dev.collection_error`, and `via: ssh` in the agent view's
dev-machine rows). Plain `name` entries are ssh-only, as before.

---

## LLM / agent endpoint

The dashboard is HTML; an agent should not scrape it. There are two machine
paths, both emitting the same compact view in **TOON** (default) or JSON.

TOON — [Token-Optimized Object Notation](https://github.com/toon-format/toon),
the same format `rch -F toon` emits — encodes arrays of objects as one header
plus rows, so per-worker keys appear once instead of N times:

```
workers[16]{id,health,used,total,cores,load,disk_free_gb,disk_pct,speed,circuit,reason}:
  worker-a,warn,0,16,64,7.4,349,61.5,74.9,closed,pressure: disk_io_high
```

Measured on a real 16-worker fleet: **3.4 KB of TOON vs 10.1 KB of JSON — 66%
fewer characters** for identical content, distilled from a 276 KB encrypted
snapshot.

### HTTP

```sh
BASE=https://your-app.vercel.app
curl "$BASE/api/fleet?view=help"                              # the contract — needs no key
curl -H "Authorization: Bearer $RCH_DASH_PASSPHRASE" "$BASE/api/fleet?view=problems"
curl -H "Authorization: Bearer $RCH_DASH_PASSPHRASE" "$BASE/api/fleet?view=diagnose&target=hz1"
curl -H "Authorization: Bearer $RCH_DASH_PASSPHRASE" "$BASE/api/fleet?format=json&view=full"
```

| Param | Values | Default |
|---|---|---|
| `view` | `summary` (overview + problems + per-machine/worker rows) · `problems` (problems + next actions only — the cheapest poll) · `full` (+ hints, recent builds, worker detail, history) · `diagnose` (everything about ONE target) · `help` (the contract, no key needed) | `summary` |
| `target` | a dev machine id or worker id; filters any view, required by `diagnose`. A box that is both (dispatches *and* takes builds) returns both halves; `dev:hz1` / `worker:hz1` picks one. Unknown id → `404` listing the known ids | — |
| `format` | `toon`, `json` | `toon` |

Key via `Authorization: Bearer PASSPHRASE`, `X-Fleet-Key: PASSPHRASE`, or
`?key=` (last resort — query strings land in logs and shell history).

**The passphrase is the credential *and* the decryption key, and the host never
stores it.** The function ships only the same ciphertext the browser downloads;
it derives the AES key from whatever the caller sends, in-request. A wrong
passphrase fails the GCM auth tag and returns 401. There is no separate API
token to leak, and no way to get plaintext out of the endpoint without already
being able to decrypt the published snapshot yourself.

Responses: `200` body · `400` bad `format`/`view`, or `diagnose` without a
`target` · `401` missing or wrong key · `404` unknown `target` (the body lists
every known id) · `405` non-GET · `500` no snapshot bundled. Errors are one
line of plain text that names the fix, so an agent can branch on them cheaply. `Cache-Control: no-store` throughout — a
cached fleet view that looks live is the exact failure this project exists to
prevent.

If your host also gates access (Vercel Deployment Protection is on by default),
the agent needs that host token too — e.g. `vercel curl`, or a
protection-bypass header.

### Local (no network, no auth dance)

For agents already running on a fleet machine:

```sh
npm run llm -- --view help                       # the contract; no passphrase needed
npm run llm -- --view problems                   # problems + next actions (cheapest)
npm run llm -- --view diagnose --target hz1      # everything about one machine or worker
npm run llm -- --target css                      # summary filtered to one entity
npm run llm -- --format json --view full
npm run llm -- --url "$BASE/data/fleet.enc.json"
```

Passphrase resolution: `RCH_DASH_PASSPHRASE`, then `./.env`, then Vault.
Exit codes: `2` no passphrase, `3` unreadable snapshot, `4` wrong passphrase,
`5` unknown target (stderr lists the known ids).

### Shape

```
schema, label, generated_at, age_seconds, stale
verdict                                     one line: "N critical problems — read problems[]" / "fleet healthy"
summary{...}                                fleet health, incl. hooks_missing, local_builds_running,
                                            daemon_version, version_skew, problems_critical/warn
problems[]{severity,kind,target,detail,since,action,on}
                                            critical first — act on these
next_actions[]{severity,on,run,fixes}       the problems folded into distinct commands, per machine
dev_machines[]{id,level,posture,offload_pct,basis,remote_builds,local_builds,
               local_now,hook,shim,doctor,workers_healthy,...,version,uptime_h}
workers[]{id,health,used,total,cores,load,disk_free_gb,disk_pct,speed,circuit,tags,reason}
# view=full adds dev_detail[] (hints, alerts, issues, active/queued builds
# with stall detectors, hook/shim/doctor, convergence, recent builds),
# worker_detail[] (pressure confidence/rule, recovery, bypass, probe history,
# per-dev-machine slot readings) and history[]
# view=diagnose&target=X adds the target's detail, its pool as seen from that
# box (dev machine) or what every dev machine says about it (worker)
```

Every `problems[]` row carries **`action`** (the command to run) and **`on`**
(where to run it: a dev machine id, `collector` for the box that publishes the
dashboard, or empty when informational), and `since` when the daemon's own
alert lifecycle knows when it started. The kinds it can emit, with meaning and
fix, are served by `?view=help`:

| kind | severity | means |
|---|---|---|
| `dev.hook_missing` | critical / warn | Claude Code's PreToolUse hook is not installed. Critical when no working cargo shim is on the box either (nothing is intercepted); warn when the shim still covers cargo (bun/gcc/make/nix builds from agents run locally) |
| `dev.unmanaged_local_builds` | critical | compiler processes running **right now** with no rch ancestor (`rch shim status`). Linux dev machines only — rch's detector reads `/proc`, so a macOS box always reports 0 |
| `dev.local-only` / `dev.unreachable` | critical | posture local, or the collector could not get `rch status` (the detail says whether ssh, rch or rchd failed) |
| `dev.doctor_failed` / `dev.doctor_warnings` | critical / warn | `rch doctor` findings on the dev machine, with `rch doctor --fix` when fixable |
| `dev.shim_missing` / `dev.shim_stale` | warn | cargo shim absent, out of date, or shadowed on PATH |
| `dev.daemon_version_skew` | warn | this box runs a different rch than the fleet |
| `dev.collection_error` | warn | one probe failed; those columns are **unknown, not fine** |
| `dev.degraded` | warn | partial remote capability for a reason not shared fleet-wide |
| `fleet.degraded` | warn | ≥2 dev machines degraded by the **same** sick workers — one root cause, listed once, naming the workers to fix (replaces N identical per-machine rows) |
| `worker.offline` / `worker.critical` / `worker.warn` | critical / critical / warn | as before, now with `since`, circuit recovery countdown, bypass code, pressure confidence, and rch's own suggested action |
| `worker.convergence_drift` | warn | worker missing repos a dev machine's builds need |
| `build.hook_dead` / `build.stalled` | critical / warn | an active build whose dispatching hook is gone (slots leak until `rch cancel <id>`), or that has stopped heartbeating and progressing |
| `snapshot.stale` / `snapshot.timestamp_unreadable` | critical | this feed itself |

Worker "last seen" is judged against **snapshot** time, not the reader's
clock, so an old snapshot reports itself stale rather than declaring the whole
fleet offline.

The browser's **Problems** panel and both agent paths are fed by one module
(`src/problems.js`) on top of one distiller (`tools/llm-view.mjs`), so the HTTP
output, the local CLI and the page cannot disagree about what is broken or what
fixes it; `npm run test:llm` proves the browser and endpoint paths emit
byte-identical rows.

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
| `rch status --json` | posture, daemon, derated slots, pressure (state, reason, confidence, policy rule), circuit state + recovery countdown, bypass records, recent builds, remote/local counts, remediation hints, **alerts** (with first-seen), **issues** (with the daemon's remediation command), **active builds with stall detectors**, queued builds, repo convergence, test counters |
| `rch workers capabilities --json` | cores, load average, toolchain versions |
| `rch workers list --json` | tags, priority (static config) |
| `:9100/metrics` | probe latency, last-seen timestamps |
| `rch doctor --json` | the dev machine's own self-checks: hook wired, daemon socket up, config valid, SSH keys — only non-passing checks are shipped |
| `rch shim status --json` | cargo shim installed / current / first on PATH, and **compiler processes running outside rch right now** |
| `rch hook status --json` | PreToolUse hook install state per agent (Claude Code, Codex, Gemini, Continue) |

All seven run concurrently on the far side of **one** ssh connection per dev
machine (~2–4 s for the whole fleet). A probe that does not answer — an older
`rch` without `shim status`, say — is reported as *unknown* for that machine
(`dev.collection_error`), never as fine.

Facts are unioned across dev machines, so one unreachable box cannot blank the
fleet view. Each worker records which machines can see it, and its slot counts
per machine — because `rchd` derates independently on each.

---

## Testing

```sh
npm run build                # bakes the Vite base path (RCH_DASH_BASE) into dist/
npm run serve:dist &         # vite preview on 127.0.0.1:4174, honoring that base
RCH_DASH_PASSPHRASE='...' npm run test:e2e
                             # pass RCH_DASH_BASE=/ too if you built with it
```

Drives real Chromium against a real encrypted snapshot: gate, wrong-vs-right
passphrase, rendering, drawers, filtering, theme, cookie session, lock, mobile
overflow, console errors. This test is what caught a slot double-count that
reported 198 build slots for an 80-slot fleet.

## Layout

```
dashboard/
  tools/snapshot.mjs        collector + encryptor (Node, no dependencies)
  tools/llm-view.mjs        the agent views (summary/problems/full/diagnose/help)
  tools/fleet-llm.mjs       local CLI over the same views (npm run llm)
  api/fleet.mjs             GET /api/fleet — the same views over HTTP
  src/problems.js           problem + next-action derivation, shared by page and endpoint
  scripts/publish-snapshot.sh  collect + upload the ciphertext to Vercel Blob (the 2-minute tick)
  scripts/deploy-vercel.sh  build + prebuilt deploy to Vercel (the hourly / on-change tick)
  scripts/deploy.sh         build + deploy to GitHub Pages
  ../packaging/launchd/     the macOS schedules for both ticks
  tests/snapshot.mjs        collector units (probe framing, section isolation, merge)
  tests/parity.mjs          browser vs endpoint classifiers + problem rows must agree
  tests/endpoint.mjs        /api/fleet against the real bundle and live snapshot
  tests/e2e.mjs             browser end-to-end smoke test
  tests/prod-check.mjs      the deployed URL: gate, unlock, map, problems, endpoint
  src/crypto.ts             PBKDF2 + AES-GCM + cookie session
  src/derive.ts             health + posture classification
  src/App.tsx               layout, filtering, sorting
  src/components/           Gate, Problems, WorkerCard/Drawer, DevMachineCard/Drawer, Sparkline
  src/styles.css            design tokens (dark + light)
```

## Base path

Vercel serves at the root, which is the default for `deploy-vercel.sh`
(`RCH_DASH_BASE=/`). GitHub Pages project sites serve from `/<repo>/`:

```sh
RCH_DASH_BASE=/my-repo/ npm run build
```
