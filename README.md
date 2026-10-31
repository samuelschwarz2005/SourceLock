# SourceLock

SourceLock is a lightweight FiveM security utility built to stop backdoors and script dumping. It uses an external Node.js scanner to catch obfuscated "cipher" code, hidden webhooks, and rogue requests before boot. At runtime, a dynamic server-to-client Lua loader keeps scripts out of the manifest, protecting code from memory dumpers.

```
scanner.js                          # Part 1 — external anti-backdoor scanner (Node, zero deps)
SourceLock/                         # Part 2 — runtime loader resource
├── fxmanifest.lua                  # payload intentionally absent from client_scripts
├── config.lua                      # shared config, logging, FNV-1a hash, chunk env
├── server/main.lua                 # payload cache, ticket handshake, chunked delivery
└── client/
    ├── init.lua                    # handshake client, assembles + load()s the payload
    └── payload/
        └── client_logic.lua        # the protected chunk (never in the manifest)
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
node scanner.js --help
```

No npm install required — it only uses `node:fs/promises` and `node:path`.

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

Each hit prints the file, `line:column`, the rule and the offending snippet. High-risk lines are red, medium yellow, and hits beyond the per-rule cap per file are summarised instead of flooding the terminal.

### Editing the whitelist

Everything you normally touch lives in the `CONFIG` block at the top of `scanner.js`:

- **`WHITELIST`** — files and directories to skip. Entries are case-insensitive substrings of the path relative to the target root, `*` is a wildcard, and a trailing `/` prunes a whole directory. It ships covering build tooling (`yarn/`, `webpack/`, `node_modules/`, `dist/`) and official Cfx.re resources (`[cfx]/`, `sessionmanager/`, `mapmanager/`, …). Every entry is a blind spot, so keep it short.
- **`ALLOWED_DOMAINS`** — hosts that `PerformHttpRequest`/`fetch` may legally reach. Sub-domains match (`api.cfx.re` matches `cfx.re`). Anything else is reported high. **Add your own API host here.**
- **`maxFileBytes`**, **`findingsPerRule`**, **`snippetWidth`**, **`ignorePrivateIps`** — tuning knobs.

### Limitations of static scanning

Pattern matching finds *strings*, not intent. A backend written in one long encoded line will be caught; a backdoor written in plain, boring-looking Lua that only `PerformHttpRequest`s at 3am will not. Treat the scanner as a first pass — `SL003`, `SL011` and `SL013` in particular need human eyes — and always review `high` hits by hand.

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
```

Server-side defences on the delivery event:

- **Bound to the requester.** The payload is only ever sent to the `source` of the request; no source id is accepted as a parameter, so one player cannot fetch another's code.
- **Single-use, expiring ticket.** Every delivered sequence needs a fresh challenge token that is invalidated the moment it is echoed, matched or not, and dies after `challengeTtl`.
- **Rate limited twice.** A minimum gap between challenges plus a per-minute budget, and a separate cooldown between successful deliveries — spamming the event gets silently throttled, never extra payloads.
- **Integrity checked.** The client re-hashes the assembled text and refuses to run anything that is not the byte-for-byte file the server read from disk.
- **Text-only chunks.** `load(..., 't')` so no bytecode blob can be smuggled in.

Tuning is all in `config.lua` (`challengeTtl`, `challengeBudget`, `deliveryCooldown`, `chunkSize`, `debug`). Set `SourceLock.debug = true` to trace tickets and deliveries while testing.

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
