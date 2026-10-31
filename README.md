# SourceLock

SourceLock is a lightweight FiveM security utility built to stop backdoors and script dumping. It uses an external Node.js scanner to catch obfuscated "cipher" code, hidden webhooks, and rogue requests before boot. At runtime, a dynamic server-to-client Lua loader keeps scripts out of the manifest, protecting code from memory dumpers.

```
scanner.js                          # Part 1 — external anti-backdoor scanner (Node, zero deps)
lib/trust.js                        # finding fingerprints + trust list (scanner and bot)
lib/discord-report.js               # embed building + webhook posting
bot/index.js                        # Discord bot: /scan, /trust, /untrust, /trustlist
SourceLock/                         # Part 2 — runtime loader resource
├── fxmanifest.lua                  # payload intentionally absent from client_scripts
├── config.lua                      # shared config, logging, FNV-1a hash, chunk env
├── server/main.lua                 # payload cache, ticket handshake, chunked delivery
└── client/
    ├── init.lua                    # handshake client, assembles + load()s the payload
    └── payload/
        └── client_logic.lua        # the protected chunk (never in the manifest)

package.json                        # scripts + discord.js (bot only)
.env.example                        # env var names, no secrets
```

---

## Part 1 — `scanner.js`

A standalone scanner you run **before booting the server** (or in CI on every commit).

### Usage

```bash
node scanner.js                      # scans ./resources
node scanner.js ./resources          # explicit target
node scanner.js ./resources --strict # fail on medium findings too
node scanner.js ./resources --json   # machine-readable output for CI
node scanner.js ./resources --all    # every hit, no per-rule cap
node scanner.js ./resources --webhook "$URL"   # post the report to Discord
node scanner.js ./resources --no-trust        # ignore the trust list
node scanner.js --help
```

No npm install required: the scanner uses Node built-ins plus its own `lib/` helpers. Only the Discord bot needs `npm install`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings matching the current policy |
| `1` | High-risk findings present (or medium with `--strict`) |
| `2` | Scanner error — target missing or unreadable |

That makes it usable as a boot gate:

```bash
node scanner.js ./resources || { echo "Refusing to boot: backdoor signatures found"; exit 1; }
```

### Detection rules

| ID | Severity | Detects |
| --- | --- | --- |
| SL001 | high | `loadstring(` |
| SL002 | high | `assert(load(` |
| SL003 | medium | `load(` dynamic chunks (noisy — verify by hand) |
| SL004 | high | `frombase64(` |
| SL005 | high | `\xNN` hex byte escapes |
| SL006 | high | `\0` / `\123` NUL and decimal byte escapes |
| SL007 | medium | `atob(` / `Buffer.from(..., 'base64')` in JS & NUI (`.js`, `.html`) |
| SL008 | high | `os.execute(` |
| SL009 | high | `io.popen(` |
| SL010 | high | Discord webhook URLs |
| SL011 | medium | `PerformHttpRequest` / `fetch` with a non-literal URL |
| SL012 | high | `PerformHttpRequest` / `fetch` to a domain outside `ALLOWED_DOMAINS` |
| SL013 | medium | Hard-coded public IPv4 addresses |
| SL014 | high | Compiled Lua bytecode (`.luac` or an `\x1bLua` header) — cannot be reviewed |
| SL015 | medium | Binary/NUL bytes inside a source file — obfuscation or corruption |
| SL016 | medium | File is over `maxFileBytes`, so it was **reported instead of pattern-scanned** |
| SL017 | medium | File could not be read — check permissions and inspect by hand |

Each hit prints the file, `line:column`, the rule and the offending snippet. High-risk lines are red, medium yellow, and hits beyond the per-rule cap per file are summarised instead of flooding the terminal.

### Editing the whitelist

Everything you normally touch lives in the `CONFIG` block at the top of `scanner.js`:

- **`WHITELIST`** — files and directories to skip. Entries are case-insensitive substrings of the path relative to the target root, `*` is a wildcard, and a trailing `/` prunes a whole directory. It ships covering build tooling (`yarn/`, `webpack/`, `node_modules/`, `dist/`) and official Cfx.re resources (`[cfx]/`, `sessionmanager/`, `mapmanager/`, …). Every entry is a blind spot, so keep it short.
- **`ALLOWED_DOMAINS`** — hosts that `PerformHttpRequest`/`fetch` may legally reach. Sub-domains match (`api.cfx.re` matches `cfx.re`). Anything else is reported high. Raw code and paste hosts (`github.com`, `raw.githubusercontent.com`, `pastebin.com`, `transfer.sh`, file CDNs) are deliberately **not** allowlisted: that is where staged payloads are fetched from. **Add only hosts you control.**
- **`maxFileBytes`**, **`findingsPerRule`**, **`snippetWidth`**, **`ignorePrivateIps`** — tuning knobs.

### Limitations of static scanning

Pattern matching finds *strings*, not intent. A backend written in one long encoded line will be caught; a backdoor written in plain, boring-looking Lua that only `PerformHttpRequest`s at 3am will not. Treat the scanner as a first pass — `SL003`, `SL011` and `SL013` in particular need human eyes — and always review `high` hits by hand.

Lines that begin with a comment marker (`--`, `//`, `<!--`) are skipped because inert comments cannot execute; this removes most framework noise. Inline comments and lines inside long comments/strings are still scanned, so hiding code in a comment block does not help an attacker.

---

## Part 2 — the `SourceLock` runtime loader

### Install

1. Drop the `SourceLock/` folder into `resources/`.
2. Add it to `server.cfg`: `ensure SourceLock` (after your framework resources).
3. Put your real client code in `client/payload/client_logic.lua` (or point `SourceLock.payloadFile` in `config.lua` at another file inside the resource).
4. **Never** list the payload in `client_scripts` or `files {}`. Check it into a private repo — it is the one file that must never leak.

### Handshake flow

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

Server-side defences on the delivery event:

- **Bound to the requester.** The payload is only ever sent to the `source` of the request; no source id is accepted as a parameter, so one player cannot fetch another's code.
- **Single-use, expiring ticket.** Every delivered sequence needs a fresh challenge token that is invalidated the moment it is echoed, matched or not, and dies after `challengeTtl`.
- **Rate limited twice.** A minimum gap between challenges plus a per-minute budget, and a separate cooldown between successful deliveries — spamming the event gets silently throttled, never extra payloads.
- **Integrity checked.** The client re-hashes the assembled text and refuses to run anything that is not the byte-for-byte file the server read from disk.
- **Text-only chunks.** `load(..., 't')` so no bytecode blob can be smuggled in.
- **One delivery at a time.** The server holds an in-flight lock until the client acknowledges assembly, so two transfers can never interleave and corrupt the buffer.
- **Response throttle.** Tickets and challenge responses each have their own per-minute budget, so an executor hammering either event is dropped before any work happens.
- **Payload size cap.** A payload over `maxPayloadBytes` is refused at boot instead of being cached and streamed.

Tuning is all in `config.lua` (`challengeTtl`, `challengeBudget`, `maxResponses`, `deliveryCooldown`, `deliveryTimeout`, `chunkSize`, `maxPayloadBytes`, `debug`). Every value is clamped by `SourceLock.sanitize()` at load, so a mistyped setting degrades safely instead of hanging the server. Set `SourceLock.debug = true` to trace tickets and deliveries while testing.

### What the payload gets

`config.lua`'s `SourceLock.createEnv()` builds the chunk environment: `__index = _G`, so natives, `CreateThread`, `RegisterCommand` and `exports` work as usual, plus a stable `SL` table:

```lua
SL.log(fmt, ...)   -- prefixed console logging
SL.version         -- loader version
SL.resource        -- resource name
SL.hash(string)    -- the shared FNV-1a
```

### Honest security limits — read this

This design raises the cost of dumping; it does not make client code secret. Concretely:

- **Anything the client runs, the client can read.** By the time `load()` executes, your source is in the client's Lua state. A determined attacker can hook `load`, dump the shared string table, or walk memory. An executor user with a `loadstring` hook will catch the payload on delivery.
- **What it does stop:** `resources/` cache browsing, manifest-based rippers, "download the resource from the server" scripts, and casual copy-paste theft — the payload is not in `client_scripts`, so it is not part of the cached resource script set.
- **Client-side checks are advisory.** Any anti-tamper check you add inside the payload can be removed by the same attacker. Keep gameplay authority on the server: money, items, damage and cooldowns must be validated server-side regardless of what the client claims.
- **The handshake is not authentication.** `clientReady` is client-controlled, so a modded client can ask for the payload immediately. The token/rate-limiting exist to stop *other players and blind event spam*, not to distinguish a real client from a modded one.
- If you need real code protection on FiveM, combine this with asset escrow for NUI/bundled assets and, above all, server-authoritative logic.

Recommended baseline for a live server: the scanner as a boot gate, escrow for any shipped NUI/js, and the rule that the client never decides anything that matters.

---

## Discord reporting and the bot

These are two separate pieces, because an incoming webhook can only be posted *to* — it cannot receive commands.

### Reporting from the scanner

```bash
export SOURCELOCK_WEBHOOK_URL='https://discord.com/api/webhooks/000000000000000000/replace-with-your-own-token'
node scanner.js ./resources                    # report posted automatically
node scanner.js ./resources --webhook "$URL"   # or per run
```

The URL above and in `.env.example` is a placeholder. Use your own webhook and keep it in the environment (`SOURCELOCK_WEBHOOK_URL`), never in the repository: anyone holding the URL can post to that channel.

The report is written to be readable without knowing the rule table:

- a headline that says what happened — *"2 high-risk findings"*, *"3 warnings"* or *"clear"*;
- a colour: red = act before booting, amber = review, green = nothing to fix;
- one card per finding (up to 8) with **File**, **Why it matters** in plain English, the **Code** line, and the `/trust` command that accepts it;
- a `➕ N more findings` card when the full list does not fit;
- a `✅ Trusted, not counted` card and a `👉 What to do` section with concrete steps.

Discord's `429` retry-after is honoured with backoff. A failed post never changes the scan result or exit code — it only prints a warning.

The webhook URL is a credential: anyone holding it can post to that channel. It is accepted only from Discord's own hosts, never echoed in logs or errors, and mentions are disabled (`allowed_mentions: []`) so a hostile filename or snippet cannot ping `@everyone`.

### Running scans from Discord

```bash
npm install        # discord.js — only needed for the bot
DISCORD_TOKEN='...' DISCORD_ALLOWED_ROLE_IDS='123456789012345678' npm run bot
```

| Command | What it does |
| --- | --- |
| `/scan [path]` | runs the scanner inside `SCAN_ROOT` and replies with the same embed |
| `/trust <fingerprint> [note]` | accepts one finding so it stops blocking scans |
| `/untrust <fingerprint>` | removes a trust entry |
| `/trustlist` | lists trusted fingerprints |

Fill in `.env.example` and load it the way your host already handles secrets — export the variables, use your process manager's env-file support, or on Node 20.6+ run `node --env-file=.env bot/index.js`. Never commit it. The bot **fails closed**: with no `DISCORD_ALLOWED_ROLE_IDS` or `DISCORD_ALLOWED_USER_IDS` it refuses to start, and everyone else gets an ephemeral "not authorised". `/scan` is confined to `SCAN_ROOT` — `..` and absolute paths outside it are rejected. Commands register in `DISCORD_GUILD_ID` when set, otherwise globally. Run the bot as an unprivileged user that can read the resources folder but write only the trust file.

### Trust

Trust is per finding, never per file or rule. The fingerprint is `sha256(file + rule + normalised snippet)`, truncated to 16 hex characters:

- editing that line → new fingerprint, the trust stops applying;
- moving the line → fingerprint survives, because line numbers are excluded;
- a different rule matching the same text → still reported.

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

Trusted findings are still shown (dim `TRUST` rows) and included in `--json` with `"trusted": true`, but they do not count towards the summary or the exit code. `--no-trust` ignores the list, `--trust-file` points elsewhere, a malformed list trusts nothing rather than everything, and writes are atomic (temp file + rename). Commit the trust file if you want decisions to survive redeploys.

---

## Security review

Both halves were reviewed adversarially and hardened. What was found and fixed:

| Issue | Impact if left open | Fix |
| --- | --- | --- |
| A `\0` byte made the scanner treat a source file as binary | one-byte scan bypass | scanned as latin1 **and** reported (`SL015`) |
| Files over `maxFileBytes` were skipped silently | pad a backdoor past 2 MB to hide it | reported (`SL016`), never skipped |
| `.luac` bytecode was never opened | hidden, unreviewable code | flagged (`SL014`) and still pattern-scanned |
| `github.com` / `raw.githubusercontent.com` were allowlisted | staged payload fetches were exempt | removed from the defaults |
| The 3-hits-per-rule cap was silent | a hit could be buried behind three decoys | suppressed count is printed; `--all` shows everything |
| Unreadable files were dropped quietly | a locked-down file escaped review | reported (`SL017`) |
| No config validation (`chunkSize = 0`) | server hangs building chunks | every tunable clamped by `SourceLock.sanitize()` |
| `retryDelay = 0` | client becomes a request flood | clamped to at least 1000 ms |
| `payloadFile` could contain `..` or be absolute | read outside the resource folder | rejected at startup, default restored |
| No payload size cap | memory and bandwidth abuse | `maxPayloadBytes`, refused at boot |
| Two deliveries could interleave chunks | corrupted assemblies, wasted retries | in-flight lock released by a client ack |
| Unlimited bogus `challengeResponse` spam | free event-handler load | dedicated per-minute response budget |
| Payload re-executed after a runtime error | duplicated threads, commands and events | executed at most once per session |
| Unbounded client assembly buffer | rogue chunk events grew memory freely | per-chunk and total size bounds |
| 32-bit integrity digest | collision cheaply forgeable | two-pass 64-bit digest |
| Webhook URL could point anywhere | reports leaked to an attacker host (SSRF) | only Discord webhook endpoints accepted; localhost behind an explicit test flag |
| Hostile filenames/snippets could mention everyone | ping spam via a backdoor's file name | `allowed_mentions: []` and control characters stripped |
| Any Discord member could run scans or trust findings | one member could whitelist a backdoor | fail-closed role/user allowlist, ephemeral denial |
| `/scan` accepted arbitrary paths | read any folder on the host | resolved and confined to `SCAN_ROOT` |
| Coarse trust (whole file or rule) | a new backdoor hidden in a trusted area | per-finding fingerprint including the snippet |

Accepted by design and **not** fixable in code: the handshake is client-driven, so a modded client can request the payload immediately, and once `load()` runs the source is in the client's Lua state. See the limits section above.
