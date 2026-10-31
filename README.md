<div align="center">

# 🔐 SourceLock

**Scan before you boot. Ship code the cache cannot keep.**

[![Version](https://img.shields.io/badge/version-1.0.2-brightgreen?style=for-the-badge)](docs/release-notes/v1.0.2.md)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2018-339933?style=for-the-badge&logo=node.js&logoColor=white)](#requirements)
[![Scanner dependencies](https://img.shields.io/badge/scanner%20dependencies-0-success?style=for-the-badge)](#quick-start)
[![Tests](https://img.shields.io/badge/tests-60%20passing-success?style=for-the-badge)](#verification)
[![Platform](https://img.shields.io/badge/platform-FiveM-ff6600?style=for-the-badge)](https://fivem.net)

*Anti-backdoor scanner · config file & ignore list · server→client payload loader · Discord reporting & trust*

</div>

---

## What this is

Two independent halves, both small enough to read in an afternoon.

| Half | Question it answers | How |
| --- | --- | --- |
| **`scanner.js`** — static analysis | *Is this resource safe to boot?* | 17 rules, line-level evidence, boot-gate exit codes, JSON output |
| **`SourceLock/`** — runtime loader | *Can my client code be skimmed out of the cache?* | payload kept out of the manifest, ticketed, chunked, hashed, executed once |

Around them: readable Discord reports, a slash-command bot, and per-finding trust so a reviewed hit stops blocking you without blinding the scanner.

The scanner has **no npm dependencies** — Node built-ins plus the `lib/` helpers in this repo. Only the bot needs `npm install`.

---

## Quick start

```bash
git clone https://github.com/samuelschwarz2005/SourceLock.git
cd SourceLock

node scanner.js ./resources                 # 0 clean · 1 findings · 2 error
node scanner.js ./resources --strict        # medium findings fail too
node scanner.js ./resources --json          # CI-friendly output

npm test                                    # 60 checks, no dependencies needed
```

Optional extras:

```bash
# Report every scan to a Discord channel
export SOURCELOCK_WEBHOOK_URL='https://discord.com/api/webhooks/<id>/<token>'
node scanner.js ./resources

# Run scans from Discord
npm install
DISCORD_TOKEN='...' DISCORD_ALLOWED_ROLE_IDS='123456789012345678' npm run bot
```

### Boot gate

```bash
node scanner.js ./resources || { echo "Refusing to boot: backdoor signatures found"; exit 1; }
```

| Exit code | Meaning |
| --- | --- |
| `0` | Nothing found under the current policy (trusted findings included) |
| `1` | High-risk findings present — or medium, with `--strict` |
| `2` | Scanner error: target missing or unreadable, or a config file that will not validate |

---

## Full command reference

```
node scanner.js [directory] [options]

  directory          Folder to scan (default: ./resources, or targetDir from config)
  --json             Print JSON instead of the terminal report
  --strict           Also fail on medium-severity findings
  --all              Show every hit instead of capping at 3 per rule per file
  --no-color         Disable ANSI colours
  --webhook <url>    Post the report to a Discord webhook
  --trust-file <f>   Trust list to read (default: ./sourcelock-trust.json)
  --no-trust         Ignore the trust list entirely
  --config <file>    Settings file (default: ./.sourcelock.jsonc)
  --ignore <file>    Ignore file (default: .sourcelockignore)
  --no-config        Ignore the config file and its ignore file
  --help             Usage

Environment: SOURCELOCK_WEBHOOK_URL, SOURCELOCK_TRUST_FILE
```

An explicit `directory` argument always wins over `targetDir` in the config file.

---

## Detection rules

| ID | Severity | Detects |
| --- | --- | --- |
| `SL001` | 🔴 high | `loadstring(` |
| `SL002` | 🔴 high | `assert(load(` |
| `SL003` | 🟡 medium | `load(` with dynamic chunks — noisy, verify by hand |
| `SL004` | 🔴 high | `frombase64(` |
| `SL005` | 🔴 high | `\xNN` hex byte escapes |
| `SL006` | 🔴 high | `\0` / `\123` NUL and decimal byte escapes |
| `SL007` | 🟡 medium | `atob(` / `Buffer.from(..., 'base64')` in JS and NUI |
| `SL008` | 🔴 high | `os.execute(` |
| `SL009` | 🔴 high | `io.popen(` |
| `SL010` | 🔴 high | Discord webhook URLs |
| `SL011` | 🟡 medium | `PerformHttpRequest` / `fetch` with a non-literal URL |
| `SL012` | 🔴 high | `PerformHttpRequest` / `fetch` to a host outside `ALLOWED_DOMAINS` |
| `SL013` | 🟡 medium | Hard-coded public IPv4 addresses |
| `SL014` | 🔴 high | Compiled Lua bytecode (`.luac`, `\x1bLua` header) — cannot be reviewed |
| `SL015` | 🟡 medium | Binary / NUL bytes inside a source file — obfuscation or corruption |
| `SL016` | 🟡 medium | File over `maxFileBytes`, so it was **reported rather than pattern-scanned** |
| `SL017` | 🟡 medium | File could not be read — check permissions and inspect by hand |

Every hit prints the file, `line:column`, the rule and the offending snippet. High-risk rows are red, medium yellow. Hits beyond the per-rule cap are counted and summarised instead of flooding the terminal — `--all` shows everything.

Lines that *begin* with a comment marker (`--`, `//`, `<!--`) are skipped, because inert comments cannot execute; that removes most framework noise. Inline comments and code inside long comment blocks are still scanned, so hiding a payload in a comment block does not help an attacker.

---

## Configuration — `.sourcelock.jsonc`

Defaults live in the `DEFAULTS` block at the top of `scanner.js`. Anything server-specific belongs in `.sourcelock.jsonc` next to where you run the scanner, so pulling a SourceLock update never overwrites your settings. Copy [`.sourcelock.example.jsonc`](.sourcelock.example.jsonc) and delete what you do not need: every key is optional, comments and trailing commas are allowed, and a UTF-8 BOM is tolerated.

```jsonc
{
  // Where to scan when no directory argument is passed.
  "targetDir": "./resources",

  // Extend the shipped skip list instead of replacing it.
  "useDefaultWhitelist": false,
  "whitelist": ["resources/[cfx]/", "resources/vendor/"],

  // gitignore-style exclusions, merged with .sourcelockignore
  "ignorePatterns": ["**/*.min.js", "!keep.min.js"],

  // Rule behaviour: "off" removes a rule, "high"/"medium" re-grades it
  "rules": { "SL003": "off", "SL013": "medium" },

  // Extra hosts HTTP calls may reach; sub-domains included automatically
  "allowedDomains": ["api.myserver.com"],

  "maxFileBytes": 2097152,
  "findingsPerRule": 3,
  "snippetWidth": 160,
  "followSymlinks": false,
  "ignorePrivateIps": true
}
```

| Key | Default | Accepted values |
| --- | --- | --- |
| `targetDir` | `./resources` | non-empty string, resolved relative to the config file |
| `extensions` | `[".lua", ".js", ".html", ".luac"]` | up to 20 entries shaped like `.lua` (case-insensitive) |
| `maxFileBytes` | `2097152` (2 MB) | integer `1024` – `1073741824` |
| `findingsPerRule` | `3` | integer `1` – `1000` |
| `snippetWidth` | `160` | integer `40` – `2000` |
| `followSymlinks` | `false` | boolean |
| `ignorePrivateIps` | `true` | boolean |
| `useDefaultWhitelist` | `true` | boolean — `false` replaces the shipped list instead of extending it |
| `whitelist` | `[]` | up to 2000 entries, ≤200 chars, max 4 `*` wildcards each |
| `ignorePatterns` | `[]` | up to 2000 entries, ≤200 chars |
| `ignoreFile` | `.sourcelockignore` beside the config | path, resolved relative to the config file |
| `allowedDomains` | `[]` | up to 200 bare hostnames — no scheme, port or path |
| `rules` | `{}` | `{ "SL003": "off" \| "high" \| "medium" }`, any rule ID |

### Whitelist vs. ignore list — pick the right one

- **`whitelist`** is the shipped, path-substring style: entries are case-insensitive substrings of the path relative to the scan root, `*` acts as a wildcard, and a trailing `/` prunes a whole directory. It exists for well-known vendor folders.
- **`.sourcelockignore`** is gitignore syntax and is where local exclusions belong. If you are about to add a path to the whitelist because *your* build puts files there, use the ignore file instead — it keeps the blind spots in one auditable place.

Both are blind spots. Every line in either file is a file an attacker would love their payload to live in, so keep them short and reviewable.

### Ignore file syntax

`.sourcelockignore` sits next to the config file. `--ignore` points at a different one; an explicit path that does not exist is an error rather than a silent no-op.

| Pattern | Matches |
| --- | --- |
| `*.min.js` | any `.min.js` file in any directory |
| `**/*.min.js` | the same thing, spelled explicitly |
| `/bootstrap.lua` | a root-level `bootstrap.lua` only — anchored |
| `web/build/` | directories named `build` under `web`, and everything inside |
| `vendor/**` | everything under any `vendor` directory |
| `!keep.min.js` | re-includes a file an earlier rule ignored |

Semantics, matching git's where it matters:

- matching is **case-insensitive**;
- the **last matching rule wins**, so a later `!pattern` re-includes;
- a trailing `/` matches **directories only**;
- a leading `/`, or any pattern containing a `/`, is **anchored** to the scan root;
- comment lines (`#`) and blank lines are ignored;
- patterns containing `..`, absolute paths (`C:\…`, `/etc/…`), or control characters are **skipped with a warning** and the scan continues;
- when any negation rule exists, ignored directories are still traversed (pruning would make re-inclusion impossible).

### How validation behaves, and why

The two files are deliberately strict in opposite directions.

**Settings fail closed.** An unknown key, a wrong type, an out-of-range number, an unknown rule ID or a broken `rules` value aborts the scan with exit `2`. A typo like `"ignorePrivateIPs"` must never silently do nothing while you believe a check is on. `__proto__`, `constructor` and `prototype` are rejected outright.

**Ignore patterns fail open, loudly.** A pattern that cannot be trusted is dropped with a printed warning and the scan continues, because aborting an entire audit over one bad line is the worse outcome.

**Both files are bounded:** 256 KB each, 2000 patterns, 200 characters per pattern, 4000 lines in an ignore file. `--no-config` ignores both files for a reproducible CI run.

**No user text reaches the regex compiler.** Glob matching is a two-pointer segment matcher plus dynamic programming for `**`, so a pattern like `*a*a*a*a*a*a*a*a*` costs linear time instead of backtracking forever. Whitelist entries — which do use `*` → `.*` — are capped at four wildcards.

---

## Symlinks

`followSymlinks` is **off** by default: a linked folder can walk outside the tree you meant to audit, and a self-referential link can loop forever.

Set it to `true` and the scanner stats each entry, follows file and directory links, and keeps a `realpath` set of visited directories so cycles terminate instead of recursing until the stack dies. A link that resolves outside the target folder is a deliberate configuration, so decide that on purpose.

---

## Trust

Trust is **per finding**, never per file or per rule. The fingerprint is `sha256(file + rule + normalised snippet)` truncated to 16 hex characters:

- edit that line → new fingerprint, and the finding comes back;
- move the line → trust survives, because line numbers are excluded;
- the same text matching a different rule → still reported.

```json
{
  "version": 1,
  "entries": [
    {
      "fingerprint": "66311e209ab6a380",
      "note": "our own admin menu loader",
      "addedBy": "sam#0001 (123456789012345678)",
      "addedAt": "2026-10-31T12:00:00.000Z"
    }
  ]
}
```

Trusted findings are still shown (dim `TRUST` rows) and still appear in `--json` with `"trusted": true`, but they do not count towards the summary or the exit code. `--no-trust` ignores the list, `--trust-file` points elsewhere, a corrupt list trusts **nothing** rather than everything, and writes are atomic (temp file + rename). Commit the trust file if you want decisions to survive redeploys.

---

## Discord reporting

```bash
export SOURCELOCK_WEBHOOK_URL='https://discord.com/api/webhooks/000000000000000000/replace-with-your-own-token'
node scanner.js ./resources
```

The report is written for a human, not a grep dump:

- a **headline** that says what happened — *"2 high-risk findings"*, *"3 warnings"*, *"clear"*;
- a **colour** that carries meaning — red = act before booting, amber = review, green = nothing to fix;
- **one card per finding** (up to 8) with **File**, **Why it matters** in plain English, the **Code** line, and the `/trust` command that accepts it;
- a **`➕ N more findings`** card when the list does not fit;
- a **`✅ Trusted, not counted`** card and a **`👉 What to do`** section with concrete steps.

The webhook URL is a credential: anyone holding it can post to that channel. It is accepted only from Discord's own hosts, never echoed in logs or errors, and mentions are disabled (`allowed_mentions: []`) so a hostile filename or snippet cannot ping `@everyone`. `429` responses are honoured with backoff, and a failed post never changes the scan result or its exit code — it only prints a warning.

Preview all three report shapes in the terminal without posting anywhere — the tool sends nothing unless you pass `--send`:

```bash
node tools/preview-report.js
```

---

## The bot

```bash
npm install        # discord.js — only needed for the bot
DISCORD_TOKEN='...' DISCORD_ALLOWED_ROLE_IDS='123456789012345678' npm run bot
```

| Command | What it does |
| --- | --- |
| `/scan [path]` | runs the scanner inside `SCAN_ROOT` and replies with the same report |
| `/trust <fingerprint> [note]` | accepts one finding so it stops blocking scans |
| `/untrust <fingerprint>` | removes a trust entry |
| `/trustlist` | lists trusted fingerprints |

The bot **fails closed**: with no `DISCORD_ALLOWED_ROLE_IDS` or `DISCORD_ALLOWED_USER_IDS` it refuses to start, and everyone else gets an ephemeral "not authorised". `/scan` is confined to `SCAN_ROOT` — `..` and absolute paths outside it are rejected. Commands register in `DISCORD_GUILD_ID` when set, otherwise globally. Run it as an unprivileged user that can read the resources folder but write only the trust file.

Fill in `.env.example` and load it the way your host already handles secrets — export the variables, use your process manager's env-file support, or on Node 20.6+ run `node --env-file=.env bot/index.js`. Never commit it.

---

## The runtime loader

### Install

1. Drop the `SourceLock/` folder into `resources/`.
2. Add `ensure SourceLock` to `server.cfg`, after your framework resources.
3. Put your real client code in `SourceLock/client/payload/client_logic.lua` (or point `SourceLock.payloadFile` in `config.lua` at another file inside the resource).
4. **Never** list the payload in `client_scripts` or `files {}`. Check it into a private repo — it is the one file that must not leak.

### Handshake

```
client/init.lua                  server/main.lua
      │                                │  readPayload() → cache + FNV-1a hash
      │  playerSpawned (+ settle delay)│
      │ ─── sourcelock:clientReady ──▶ │  cooldown + per-minute budget check
      │ ◀── sourcelock:challenge ───── │  single-use token, 10s TTL
      │ ─── challengeResponse(token) ─▶ │  token match + TTL + delivery cooldown
      │ ◀── sourcelock:chunk (×N) ───── │  payload sliced into 24 KB chunks
      │ ◀── sourcelock:complete ─────── │  total + expected hash
      │  verify hash → load(..., env)   │
      │  pcall(chunk) → running         │
      │ ─── sourcelock:ack ───────────▶ │  releases the in-flight lock
```

What the server actually enforces:

- **Bound to the requester.** The payload only ever goes to the `source` of the request; no source id is accepted as a parameter, so one player cannot fetch another's code.
- **Single-use, expiring ticket.** Each delivered sequence needs a fresh token that is invalidated the moment it is echoed — matched or not — and dies after `challengeTtl`.
- **Rate limited twice.** A minimum gap between challenges plus a per-minute budget, and a separate cooldown between successful deliveries. Spamming the event gets silently throttled, never extra payloads.
- **Integrity checked.** The client re-hashes the assembled text and refuses to run anything that is not byte-for-byte the file the server read from disk.
- **Text-only chunks.** `load(..., 't')` so no bytecode blob can be smuggled in.
- **One delivery at a time.** An in-flight lock is released only by the client ack, so two transfers can never interleave.
- **Bounded.** Payload size, chunk size, assembly buffer and execution are all capped.

Tuning lives in `SourceLock/config.lua` (`challengeTtl`, `challengeBudget`, `maxResponses`, `deliveryCooldown`, `deliveryTimeout`, `chunkSize`, `maxPayloadBytes`, `debug`). Every value is clamped by `SourceLock.sanitize()` at load, so a mistyped setting degrades safely instead of hanging the server. Set `SourceLock.debug = true` to trace tickets and deliveries while testing.

### What the payload gets

`config.lua`'s `SourceLock.createEnv()` builds the chunk environment: `__index = _G`, so natives, `CreateThread`, `RegisterCommand` and `exports` work as usual, plus a stable `SL` table:

```lua
SL.log(fmt, ...)   -- prefixed console logging
SL.version         -- loader version
SL.resource        -- resource name
SL.hash(string)    -- the shared FNV-1a
```

---

## Verification

The suite is plain `node:test` — no framework, no dependencies:

```bash
npm test            # or: node --test test/
```

| File | Covers |
| --- | --- |
| `test/config.test.js` | 21 checks — JSONC parsing, key validation, merge precedence, whitelist/domain handling |
| `test/config-edge.test.js` | 12 checks — `--config` / `--ignore` / `--no-config` interplay, rule downgrades with `--strict`, BOM and trailing commas, ignore negation over traversal |
| `test/pentest.test.js` | 14 checks — escapes, oversized files, hostile paths, report content |
| `test/pentest-extra.test.js` | 13 checks — symlink following and loops, size and count limits, pathological globs |

**60 checks, all passing.** The helpers clear `SOURCELOCK_WEBHOOK_URL` for every spawned scan, so running the suite on a workstation configured for a live channel cannot post reports about fake findings.

---

## Honest limits — read this

Static matching finds *strings*, not intent, and a loader raises the cost of theft without making code secret.

**Scanner.** A backend written as one long encoded line will be caught. A backdoor written in plain, boring-looking Lua that only calls `PerformHttpRequest` at 3am will not. `SL003`, `SL011` and `SL013` are starting points for a human, not verdicts. Review every `high` hit by hand — and remember that each whitelist or ignore entry is a place the scanner will never look.

**Loader.** Anything the client runs, the client can read: once `load()` executes, the source is in the client's Lua state, and a determined attacker can hook `load`, dump the string table, or walk memory. What this design does stop is `resources/` cache browsing, manifest-based rippers, "download the resource from the server" scripts, and casual copy-paste theft. Client-side anti-tamper inside the payload can be removed by the same attacker, so keep gameplay authority on the server — money, items, damage and cooldowns must be validated server-side regardless of what a client claims.

**Handshake.** `clientReady` is client-controlled, so a modded client can ask for the payload immediately. The ticket and rate limits exist to stop *other players and blind event spam*, not to distinguish a real client from a modded one.

For real code protection on FiveM, combine this with asset escrow for NUI and bundled assets, and above all with server-authoritative logic.

---

## Security work

Both halves were reviewed adversarially; the fixes are in the code, not just in this file.

| Issue found | Impact if left open | Fix |
| --- | --- | --- |
| A `\0` byte made the scanner treat a source file as binary | one-byte scan bypass | scanned as latin1 **and** reported (`SL015`) |
| Files over `maxFileBytes` were skipped silently | pad a backdoor past 2 MB to hide it | reported (`SL016`), never skipped |
| `.luac` bytecode was never opened | hidden, unreviewable code | flagged (`SL014`) and still pattern-scanned |
| `github.com` / `raw.githubusercontent.com` allowlisted | staged payload fetches were exempt | removed from the defaults |
| Silent 3-hits-per-rule cap | bury a hit behind three decoys | suppressed count printed; `--all` shows everything |
| Unreadable files were dropped quietly | a locked-down file escaped review | reported (`SL017`) |
| `followSymlinks` never took effect | a linked file was skipped with the option apparently on | entries stat'ed, `realpath` visited-set keeps loops finite |
| `SL011`–`SL017` missing from the rule table | `rules: { "SL013": "off" }` was rejected as unknown | every emitted rule ID is registered |
| A BOM turned into part of the first ignore pattern | the first exclusion silently stopped working | BOM stripped before parsing |
| Typo in a config key | a check quietly stays on/off while you think otherwise | unknown keys abort with exit `2` |
| Pathological glob in an ignore file | scanner hangs on a crafted pattern | linear matcher, no regex for user patterns; 4-wildcard cap on whitelist |
| Ignored directory pruned despite a `!` rule | a re-included file could never be reached | pruning disabled whenever negation exists |
| `targetDir` resolved against the working directory | scans ran against the wrong tree when config lived elsewhere | resolved relative to the config file |
| `chunkSize = 0` | server hangs building chunks | every tunable clamped by `SourceLock.sanitize()` |
| `retryDelay = 0` | client becomes a request flood | clamped to at least 1000 ms |
| `payloadFile` accepted `..` or absolute paths | read outside the resource folder | rejected at startup, default restored |
| No payload size cap | memory and bandwidth abuse | `maxPayloadBytes`, refused at boot |
| Two deliveries could interleave chunks | corrupted assemblies, wasted retries | in-flight lock released by a client ack |
| Unlimited bogus `challengeResponse` spam | free event-handler load | dedicated per-minute response budget |
| Payload re-executed after a runtime error | duplicated threads, commands and events | executed at most once per session |
| Unbounded client assembly buffer | rogue chunk events grew memory freely | per-chunk and total size bounds |
| 32-bit integrity digest | collision cheaply forgeable | two-pass 64-bit digest |
| Webhook URL could point anywhere | reports leaked to an attacker host (SSRF) | only Discord webhook endpoints accepted; localhost behind an explicit test flag |
| Hostile filenames/snippets could mention everyone | ping spam via a backdoor's file name | `allowed_mentions: []`, control characters stripped |
| Any Discord member could run scans or trust findings | one member could whitelist a backdoor | fail-closed role/user allowlist, ephemeral denial |
| `/scan` accepted arbitrary paths | read any folder on the host | resolved and confined to `SCAN_ROOT` |
| Coarse trust (whole file or rule) | a new backdoor hidden in a trusted area | per-finding fingerprint including the snippet |

Accepted by design and **not** fixable in code: the handshake is client-driven, and once `load()` runs the source is in the client's Lua state.

---

## Repository layout

```
scanner.js                      anti-backdoor scanner (zero dependencies)
lib/config.js                   JSONC settings, validation, glob ignore matcher
lib/trust.js                    finding fingerprints + atomic trust list
lib/discord-report.js           embed building + webhook transport
bot/index.js                    /scan, /trust, /untrust, /trustlist
SourceLock/                     runtime loader resource
├── fxmanifest.lua              payload intentionally absent from client_scripts
├── config.lua                  shared config, logging, FNV-1a hash, chunk env
├── server/main.lua             payload cache, ticket handshake, chunked delivery
└── client/
    ├── init.lua                handshake client, assembles and load()s the payload
    └── payload/
        └── client_logic.lua    the protected chunk (never in the manifest)

test/                           60 node:test checks
tools/preview-report.js         render report samples without posting
docs/release-notes/             version notes
.sourcelock.example.jsonc       annotated settings example
.env.example                    env var names, no secrets
```

---

## Requirements

- **Node.js 18+** for the scanner, reporter and bot
- **FiveM server** for the loader resource
- **Discord** (optional): a webhook for reporting, a bot application for commands

---

## Release history

| Version | Notes |
| --- | --- |
| 1.0.2 | [Config file, ignore list, symlink fix, 60 tests](docs/release-notes/v1.0.2.md) |
| 1.0.1 | [First public release — scanner, loader, Discord reporting, trust](docs/release-notes/v1.0.1.md) |

---

<div align="center">

*Scan first. Trust deliberately. Boot anyway.*

</div>
