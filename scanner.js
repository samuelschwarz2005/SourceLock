#!/usr/bin/env node
/**
 * SourceLock — external anti-backdoor scanner for FiveM resources.
 * ---------------------------------------------------------------
 * Scans a resource tree for obfuscation, dynamic execution, hidden
 * webhooks, raw IPs and HTTP calls to untrusted hosts.
 *
 * Zero dependencies. Requires Node.js 16+.
 *
 * Usage:
 *   node scanner.js [directory] [--json] [--strict] [--all] [--no-color]
 *                   [--webhook <url>] [--trust-file <path>] [--no-trust]
 *
 *   directory        Folder to scan. Default: ./resources
 *   --json           Machine-readable output (for CI). Implies --no-color.
 *   --strict         Exit non-zero on medium findings too (default: only high).
 *   --all            Show every hit (default: 3 per rule per file, rest summarised).
 *   --no-color       Disable ANSI colours.
 *   --webhook <url>  Post the report to a Discord webhook (or SOURCELOCK_WEBHOOK_URL).
 *   --trust-file <f> Trust list to read (or SOURCELOCK_TRUST_FILE).
 *   --no-trust       Ignore the trust list entirely.
 *
 * Exit codes: 0 = clean, 1 = findings that match the selected policy,
 *             2 = scanner error (bad target, unreadable root, ...).
 *
 * Edit only the CONFIG block below for day-to-day use.
 */

'use strict';

const fsp = require('node:fs/promises');
const path = require('node:path');

const { fingerprintFinding, isTrusted, loadTrust } = require('./lib/trust');
const { postScanReport } = require('./lib/discord-report');

/* ==========================================================================
 * CONFIG — edit this block
 * ========================================================================== */

const CONFIG = {
  /** Folder scanned when no directory argument is passed. */
  targetDir: './resources',

  /**
   * Extensions that get scanned. Compared case-insensitively.
   * `.luac` is included on purpose: compiled Lua cannot be reviewed by a
   * human, so it has to be reported rather than ignored.
   */
  extensions: ['.lua', '.js', '.html', '.luac'],

  /**
   * Files larger than this are not pattern-scanned, but they are still
   * REPORTED (SL016) rather than skipped silently — otherwise padding a
   * backdoored file past the limit would hide it from the scan entirely.
   */
  maxFileBytes: 2 * 1024 * 1024,

  /** Max reported hits per rule per file; the rest are counted as suppressed. */
  findingsPerRule: 3,

  /** Longest line snippet printed / stored. */
  snippetWidth: 160,

  /** Follow directory symlinks? Off by default to avoid loops and escaping the tree. */
  followSymlinks: false,

  /**
   * Whitelist — skipped files and pruned directories.
   * Entries are case-insensitive substrings of the path relative to the target
   * folder; `*` is a wildcard and a trailing `/` marks a directory.
   * Keep this list short and explicit: every entry is a blind spot.
   */
  WHITELIST: [
    // Asset/build tooling (never ships reviewed Lua at runtime)
    'node_modules/',
    'yarn/',
    'webpack/',
    'webpack.config',
    '.yarn/',
    'vendor/',
    'dist/',
    'build/',

    // UI bundles: normally compiled, not hand-written Lua
    'web/build/',
    'web/dist/',

    // Official Cfx.re / txAdmin resources shipped with the server artifacts
    '[cfx]/',
    '[system]/',
    'cfx-server-data/',
    'monitor/',
    'chat/',
    'spawnmanager/',
    'sessionmanager/',
    'mapmanager/',
    'rconlog/',
    'hardcap/',
    'baseevents/',
    'runcode/',
    'txAdmin/',
    'txadmin/',
    'screenshot-basic/',
    'oxmysql/lib/',
  ],

  /**
   * Hosts that PerformHttpRequest / fetch may legitimately talk to.
   * Sub-domains are allowed (api.cfx.re matches cfx.re).
   * Anything else is reported as HIGH (SL012).
   *
   * Deliberately NOT included: raw code and paste hosts such as github.com,
   * raw.githubusercontent.com, gist.github.com, pastebin.com, transfer.sh and
   * file CDNs. They are the most common way a staged payload is fetched, so
   * allowlisting them would exempt exactly the traffic worth reviewing.
   * Add only hosts you control, and keep the list short.
   */
  ALLOWED_DOMAINS: [
    'cfx.re',
    'fivem.net',
    'localhost',
    '127.0.0.1',
  ],

  /** Ignore loopback / RFC1918 addresses in the raw-IP rule. */
  ignorePrivateIps: true,
};

/* ==========================================================================
 * Detection rules
 * ========================================================================== */

/**
 * `severity` — high: near-certain backdoor / shell access, block the boot.
 *              medium: needs a human to read it, often legitimate.
 * `re`       — matched once per line; findings are capped by findingsPerRule.
 * `langs`    — optional extension filter.
 */
const RULES = [
  {
    id: 'SL001',
    severity: 'high',
    title: 'loadstring() — runtime code execution',
    re: /\bloadstring\s*\(/i,
  },
  {
    id: 'SL002',
    severity: 'high',
    title: 'assert(load(...)) — runtime code execution',
    re: /assert\s*\(\s*load\s*\(/i,
  },
  {
    id: 'SL003',
    severity: 'medium',
    title: 'load(...) — dynamic chunk (verify what it loads)',
    re: /(^|[^.\w])load\s*\(/i,
  },
  {
    id: 'SL004',
    severity: 'high',
    title: 'frombase64() — encoded payload decode',
    re: /\bfrombase64\s*\(/i,
  },
  {
    id: 'SL005',
    severity: 'high',
    title: 'hex byte escapes (\\xNN) — packed/obfuscated payload',
    re: /\\x[0-9a-f]{2}/i,
  },
  {
    id: 'SL006',
    severity: 'high',
    title: 'NUL / decimal byte escapes (\\0, \\123) — packed payload',
    re: /\\0|\\[12][0-9]{2}/,
  },
  {
    id: 'SL007',
    severity: 'medium',
    title: 'base64 decode in JS/NUI code',
    re: /\batob\s*\(|Buffer\.from\s*\([^)]*['"]base64['"]/i,
    langs: ['.js', '.html'],
  },
  {
    id: 'SL008',
    severity: 'high',
    title: 'os.execute() — shell command execution',
    re: /\bos\s*\.\s*execute\s*\(/i,
  },
  {
    id: 'SL009',
    severity: 'high',
    title: 'io.popen() — shell pipe execution',
    re: /\bio\s*\.\s*popen\s*\(/i,
  },
  {
    id: 'SL010',
    severity: 'high',
    title: 'Discord webhook — common exfiltration channel',
    re: /discord(?:app)?\.com\/api\/webhooks\/\d{5,}\/[\w-]{20,}/i,
  },
];

/**
 * A line that begins with a comment marker cannot execute, so its text is
 * skipped to keep framework noise (commented-out load() calls, API docs)
 * out of the report. Inline comments and long-comment bodies are still
 * scanned: hiding real code costs more than a little noise.
 */
const COMMENT_PREFIX = { '.lua': '--', '.js': '//', '.html': '<!--' };

/** Lines that look like outbound HTTP calls; the URL itself is inspected below. */
const HTTP_CALL = /PerformHttpRequest(?:Internal)?\s*\(|\bfetch\s*\(|\bhttp\.request\b/i;
const URL_LITERAL = /https?:\/\/([^/?#\s'"`)\]}>]+)/gi;
const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b(?::\d{2,5})?/g;

/* ==========================================================================
 * CLI / colour helpers
 * ========================================================================== */

const DEFAULT_TRUST_FILE = './sourcelock-trust.json';

function parseArgs(argv) {
  const options = {
    target: null,
    json: false,
    strict: false,
    all: false,
    color: true,
    help: false,
    useTrust: true,
    webhook: process.env.SOURCELOCK_WEBHOOK_URL || null,
    trustFile: process.env.SOURCELOCK_TRUST_FILE || DEFAULT_TRUST_FILE,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (!arg.startsWith('-')) {
      if (options.target) throw new Error('only one directory argument is supported');
      options.target = arg;
      continue;
    }

    if (arg === '--json') options.json = true;
    else if (arg === '--strict') options.strict = true;
    else if (arg === '--all') options.all = true;
    else if (arg === '--no-color') options.color = false;
    else if (arg === '--no-trust') options.useTrust = false;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--webhook' || arg === '--trust-file') {
      const value = argv[index + 1];
      if (!value || value.startsWith('-')) throw new Error(`${arg} requires a value`);
      if (arg === '--webhook') options.webhook = value;
      else options.trustFile = value;
      index += 1;
    } else {
      throw new Error(`unknown option ${arg}`);
    }
  }

  return options;
}

const OPTIONS = (() => {
  try {
    return parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`SourceLock: ${error.message}`);
    console.error('Run: node scanner.js --help');
    process.exit(2);
  }
})();

if (OPTIONS.help) {
  console.log(
    [
      'SourceLock scanner',
      '',
      'Usage: node scanner.js [directory] [options]',
      '',
      '  directory        Folder to scan (default: ./resources)',
      '  --json           Print JSON instead of the terminal report',
      '  --strict         Also fail on medium-severity findings',
      '  --all            Show every hit instead of capping at 3 per rule per file',
      '  --no-color       Disable ANSI colours',
      '  --webhook <url>  Post the report to a Discord webhook',
      '  --trust-file <f> Trust list to read (default: ./sourcelock-trust.json)',
      '  --no-trust       Ignore the trust list entirely',
      '',
      'Environment: SOURCELOCK_WEBHOOK_URL, SOURCELOCK_TRUST_FILE',
    ].join('\n')
  );
  process.exit(0);
}

const useColor =
  OPTIONS.color &&
  !OPTIONS.json &&
  !process.env.NO_COLOR &&
  (Boolean(process.env.FORCE_COLOR) || process.stdout.isTTY === true);

const paint = (code, text) => (useColor ? `\u001b[${code}m${text}\u001b[0m` : text);
const color = {
  high: (text) => paint('1;31', text),
  medium: (text) => paint('1;33', text),
  ok: (text) => paint('1;32', text),
  path: (text) => paint('36', text),
  dim: (text) => paint('2', text),
  bold: (text) => paint('1', text),
};

const SEVERITY_ORDER = { high: 0, medium: 1 };

/* ==========================================================================
 * Whitelist matching
 * ========================================================================== */

function globToRegExp(glob) {
  let pattern = '';
  for (const char of glob) {
    if (char === '*') pattern += '.*';
    else if (/[.+^${}()|[\]\\?]/.test(char)) pattern += `\\${char}`;
    else pattern += char;
  }
  return new RegExp(pattern, 'i'); // substring match on the relative path
}

const whitelistMatchers = CONFIG.WHITELIST.map((entry) =>
  globToRegExp(entry.replace(/\\/g, '/'))
);

function isWhitelisted(relativePath, isDirectory) {
  const candidate = relativePath.replace(/\\/g, '/') + (isDirectory ? '/' : '');
  return whitelistMatchers.some((matcher) => matcher.test(candidate));
}

/* ==========================================================================
 * File discovery
 * ========================================================================== */

async function collectFiles(root) {
  const stats = {
    scanned: 0,
    whitelisted: 0,
    prunedDirs: 0,
    skippedLarge: 0,
    skippedBinary: 0,
    unreadable: 0,
  };

  const files = [];
  const stack = [{ absolute: root, relative: '' }];

  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;

    try {
      entries = await fsp.readdir(dir.absolute, { withFileTypes: true });
    } catch (error) {
      stats.unreadable += 1;
      if (!OPTIONS.json) {
        console.warn(color.medium(`  ! cannot read ${dir.relative || '.'}: ${error.code || error.message}`));
      }
      continue;
    }

    for (const entry of entries) {
      const relative = dir.relative ? `${dir.relative}/${entry.name}` : entry.name;
      const absolute = path.join(dir.absolute, entry.name);

      if (entry.isSymbolicLink() && !CONFIG.followSymlinks) continue;

      if (entry.isDirectory()) {
        if (isWhitelisted(relative, true)) {
          stats.prunedDirs += 1;
          continue;
        }
        stack.push({ absolute, relative });
        continue;
      }

      if (!entry.isFile()) continue;
      if (!CONFIG.extensions.includes(path.extname(entry.name).toLowerCase())) continue;

      if (isWhitelisted(relative, false)) {
        stats.whitelisted += 1;
        continue;
      }

      files.push({ absolute, relative, extension: path.extname(entry.name).toLowerCase() });
    }
  }

  // Deterministic output order.
  files.sort((a, b) => a.relative.localeCompare(b.relative));
  return { files, stats };
}

/* ==========================================================================
 * Content checks
 * ========================================================================== */

function isProbablyBinary(buffer) {
  const sample = buffer.subarray(0, 4096);
  return sample.includes(0);
}

function truncate(text, width) {
  return text.length <= width ? text : `${text.slice(0, width - 3)}...`;
}

function isPrivateIp(host) {
  const [a, b] = host.split('.').map(Number);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 192 && b === 168) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 169 && b === 254)
  );
}

function isAllowedHost(host) {
  const clean = host.toLowerCase().replace(/:\d+$/, '');
  return CONFIG.ALLOWED_DOMAINS.some((domain) => {
    const allowed = domain.toLowerCase();
    return clean === allowed || clean.endsWith(`.${allowed}`);
  });
}

/** Character ranges covered by URL literals on this line. */
function urlSpans(line) {
  const spans = [];
  URL_LITERAL.lastIndex = 0;
  let match;
  while ((match = URL_LITERAL.exec(line)) !== null) {
    spans.push([match.index, match.index + match[0].length]);
  }
  return spans;
}

/** Returns HIGH findings for literal URLs on untrusted hosts, MEDIUM otherwise. */
function inspectHttpCall(line) {
  if (!HTTP_CALL.test(line)) return [];

  const hosts = [];
  URL_LITERAL.lastIndex = 0;
  let match;
  while ((match = URL_LITERAL.exec(line)) !== null) {
    const host = match[1].split('@').pop(); // drop userinfo
    hosts.push(host);
  }

  if (hosts.length === 0) {
    return [
      {
        ruleId: 'SL011',
        severity: 'medium',
        title: 'HTTP request with a non-literal URL — confirm the destination',
      },
    ];
  }

  const findings = [];
  for (const host of hosts) {
    if (isAllowedHost(host)) continue;
    findings.push({
      ruleId: 'SL012',
      severity: 'high',
      title: `HTTP request to untrusted domain: ${host}`,
    });
  }
  return findings;
}

/** Returns MEDIUM findings for hard-coded public IPv4 addresses. */
function inspectIpAddresses(line) {
  const findings = [];
  IPV4.lastIndex = 0;
  let match;
  while ((match = IPV4.exec(line)) !== null) {
    const host = match[0].replace(/:\d+$/, '');
    if (CONFIG.ignorePrivateIps && isPrivateIp(host)) continue;
    findings.push({
      ruleId: 'SL013',
      severity: 'medium',
      title: `hard-coded IP address: ${match[0]}`,
      column: match.index + 1,
    });
  }
  return findings;
}

/* ==========================================================================
 * Scanner
 * ========================================================================== */

function describeBytes(buffer) {
  const hex = buffer.subarray(0, 16).toString('hex');
  if (!hex) return '(empty file)';
  return `first bytes: ${hex.match(/.{1,2}/g).join(' ')}`;
}

async function scanFile(file, stats) {
  let buffer;
  try {
    buffer = await fsp.readFile(file.absolute);
  } catch (error) {
    stats.unreadable += 1;
    // Never drop a file quietly: an unreadable file is exactly the kind of
    // thing worth a human look, and a silent skip is a scan bypass.
    return [
      {
        file: file.relative,
        line: 0,
        column: 0,
        ruleId: 'SL017',
        severity: 'medium',
        title: 'file could not be read — check permissions and inspect it by hand',
        snippet: '',
        suppressed: false,
      },
    ];
  }

  const findings = [];
  const perRule = new Map();
  const ruleCap = OPTIONS.all ? Number.POSITIVE_INFINITY : CONFIG.findingsPerRule;

  const looksLikeBytecode =
    file.extension === '.luac' || buffer.subarray(0, 4).toString('latin1') === '\u001bLua';
  const isBinary = isProbablyBinary(buffer);

  // Bytecode and NUL-padded files used to be skipped as "binary", which is a
  // one-byte scan bypass. Report them, then still scan their bytes as latin1.
  if (looksLikeBytecode || isBinary) {
    findings.push({
      file: file.relative,
      line: 1,
      column: 1,
      ruleId: looksLikeBytecode ? 'SL014' : 'SL015',
      severity: looksLikeBytecode ? 'high' : 'medium',
      title: looksLikeBytecode
        ? 'compiled Lua bytecode — cannot be reviewed, treat as untrusted'
        : 'binary/NUL content in a source file — obfuscation or corruption',
      snippet: describeBytes(buffer),
      suppressed: false,
    });
  }

  if (buffer.length > CONFIG.maxFileBytes) {
    stats.skippedLarge += 1;
    findings.push({
      file: file.relative,
      line: 0,
      column: 0,
      ruleId: 'SL016',
      severity: 'medium',
      title: `file is ${buffer.length} bytes, over the ${CONFIG.maxFileBytes} byte scan limit — not pattern-scanned`,
      snippet: '',
      suppressed: false,
    });
    return findings;
  }

  if (isBinary) stats.skippedBinary += 1;
  stats.scanned += 1;

  const lines = (isBinary ? buffer.toString('latin1') : buffer.toString('utf8')).split(
    /\r\n|\n|\r/
  );

  const record = (lineNumber, line, hit, column) => {
    const seen = perRule.get(hit.ruleId) || 0;
    perRule.set(hit.ruleId, seen + 1);
    if (seen >= ruleCap) return;

    findings.push({
      file: file.relative,
      line: lineNumber,
      column,
      ruleId: hit.ruleId,
      severity: hit.severity,
      title: hit.title,
      snippet: truncate(line.trim(), CONFIG.snippetWidth),
      suppressed: false,
    });
  };

  const commentPrefix = COMMENT_PREFIX[file.extension];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim().length === 0) continue;
    if (commentPrefix && line.trimStart().startsWith(commentPrefix)) continue;

    for (const rule of RULES) {
      if (rule.langs && !rule.langs.includes(file.extension)) continue;
      const match = rule.re.exec(line);
      if (!match) continue;
      record(
        index + 1,
        line,
        { ruleId: rule.id, severity: rule.severity, title: rule.title },
        match.index + 1
      );
    }

    const httpHits = inspectHttpCall(line);
    if (httpHits.length > 0) {
      const column = Math.max(1, line.search(HTTP_CALL) + 1);
      for (const hit of httpHits) record(index + 1, line, hit, column);
    }

    const ipHits = inspectIpAddresses(line);
    if (ipHits.length > 0) {
      const spans = urlSpans(line);
      for (const hit of ipHits) {
        // An IP that only makes up an already-inspected URL host adds noise.
        const offset = hit.column - 1;
        if (spans.some(([start, end]) => offset >= start && offset < end)) continue;
        record(index + 1, line, hit, hit.column);
      }
    }
  }

  // Mark findings that were dropped by the per-rule cap so the report is honest.
  for (const [ruleId, total] of perRule) {
    if (total <= ruleCap) continue;
    const extra = total - ruleCap;
    findings.push({
      file: file.relative,
      line: 0,
      column: 0,
      ruleId,
      severity: 'info',
      title: `${extra} further ${ruleId} hit(s) in this file not shown`,
      snippet: '',
      suppressed: true,
    });
  }

  return findings;
}

function loadTrustSafely(filePath) {
  try {
    return loadTrust(filePath);
  } catch (error) {
    // Fail closed: an unreadable trust list trusts nothing, it never hides findings.
    console.warn(color.medium(`  ! trust list ignored: ${error.message}`));
    return { version: 1, entries: [] };
  }
}

async function main() {
  const target = path.resolve(OPTIONS.target || CONFIG.targetDir);

  try {
    const stat = await fsp.stat(target);
    if (!stat.isDirectory()) throw new Error('not a directory');
  } catch (error) {
    console.error(color.high(`SourceLock: cannot scan "${target}" (${error.message})`));
    process.exit(2);
  }

  const started = Date.now();
  const { files, stats } = await collectFiles(target);
  const findings = [];

  for (const file of files) {
    const fileFindings = await scanFile(file, stats);
    for (const finding of fileFindings) findings.push(finding);
  }

  // Attach a stable fingerprint (file + rule + snippet) so one finding can be
  // trusted on its own, and stays trusted only while that code is unchanged.
  const trust = OPTIONS.useTrust ? loadTrustSafely(OPTIONS.trustFile) : { version: 1, entries: [] };
  for (const finding of findings) {
    finding.fingerprint = fingerprintFinding(finding);
    finding.trusted = !finding.suppressed && isTrusted(trust, finding);
  }

  // Group by file so each path is printed once, with its high-risk hits first.
  findings.sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      a.line - b.line
  );

  const actionable = findings.filter((finding) => !finding.suppressed && !finding.trusted);
  const summary = {
    high: actionable.filter((finding) => finding.severity === 'high').length,
    medium: actionable.filter((finding) => finding.severity === 'medium').length,
    trusted: findings.filter((finding) => finding.trusted).length,
    filesAffected: new Set(actionable.map((finding) => finding.file)).size,
  };

  const durationMs = Date.now() - started;
  const scannedAt = new Date().toISOString();
  const result = { target, scannedAt, durationMs, stats, summary, findings };

  if (OPTIONS.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printReport({ ...result, files });
  }

  if (OPTIONS.webhook) {
    try {
      await postScanReport(OPTIONS.webhook, result);
      if (!OPTIONS.json) console.log(color.dim('  report posted to Discord'));
    } catch (error) {
      // Reporting must never change the scan result or its exit code.
      console.error(color.medium(`  ! Discord report not sent: ${error.message}`));
    }
  }

  const failed = summary.high > 0 || (OPTIONS.strict && summary.medium > 0);
  process.exit(failed ? 1 : 0);
}

function printReport({ target, files, stats, findings, summary, durationMs }) {
  console.log('');
  console.log(color.bold('SourceLock — anti-backdoor scan'));
  console.log(color.dim(`  target : ${target}`));
  console.log(
    color.dim(
      `  files  : ${stats.scanned}/${files.length} scanned` +
        (stats.whitelisted ? `, ${stats.whitelisted} whitelisted` : '') +
        (stats.prunedDirs ? `, ${stats.prunedDirs} dirs pruned` : '') +
        (stats.skippedLarge ? `, ${stats.skippedLarge} over the size limit` : '') +
        (stats.skippedBinary ? `, ${stats.skippedBinary} with binary content (scanned anyway)` : '') +
        (stats.unreadable ? `, ${stats.unreadable} unreadable` : '')
    )
  );

  if (stats.prunedDirs > 0 || stats.whitelisted > 0) {
    console.log(color.dim('  note   : whitelisted/pruned paths were NOT scanned — keep WHITELIST short'));
  }

  console.log('');

  if (findings.length === 0) {
    console.log(color.ok('  ✔ No suspicious patterns found.'));
    console.log(color.dim(`  completed in ${durationMs} ms`));
    console.log('');
    return;
  }

  let currentFile = null;
  for (const finding of findings) {
    if (finding.file !== currentFile) {
      currentFile = finding.file;
      console.log(`  ${color.path(finding.file)}`);
    }

    if (finding.suppressed) {
      console.log(`    ${color.dim(`… ${finding.title}`)}`);
      continue;
    }

    if (finding.trusted) {
      console.log(`    ${color.dim('TRUST ')} ${color.dim(finding.ruleId)}  ${color.dim(finding.title)}`);
      if (finding.snippet) {
        console.log(`           ${color.dim(`${finding.file}:${finding.line}`)}  ${color.dim(finding.snippet)}`);
      }
      continue;
    }

    const tag =
      finding.severity === 'high'
        ? color.high('HIGH  ')
        : color.medium('MEDIUM');
    const location =
      finding.line > 0
        ? color.dim(`${finding.file}:${finding.line}:${finding.column}`)
        : color.dim(finding.file);
    console.log(`    ${tag} ${color.bold(finding.ruleId)}  ${finding.title}`);
    console.log(`           ${location}${finding.snippet ? `  ${color.dim(finding.snippet)}` : ''}`);
  }

  console.log('');
  const parts = [];
  if (summary.high) parts.push(color.high(`${summary.high} high`));
  if (summary.medium) parts.push(color.medium(`${summary.medium} medium`));
  if (summary.trusted) parts.push(color.dim(`${summary.trusted} trusted`));
  if (parts.length === 0) parts.push(color.ok('0 actionable'));
  const suppressedCount = findings.filter((finding) => finding.suppressed).length;
  const scope = summary.filesAffected > 0 ? ` across ${summary.filesAffected} file(s)` : '';
  console.log(`  ${color.bold('Summary:')} ${parts.join(', ')}${scope} — ${durationMs} ms`);
  if (suppressedCount > 0) {
    console.log(
      color.medium(
        `  ${suppressedCount} further hit(s) hidden by the ${CONFIG.findingsPerRule}-per-rule cap — rerun with --all to see every one.`
      )
    );
  }

  if (summary.high > 0) {
    console.log(color.high('  Blocked: high-risk findings present. Do not boot with these unresolved.'));
  } else if (summary.medium > 0) {
    console.log(color.dim('  Review medium findings manually; rerun with --strict to fail on them in CI.'));
  }
  console.log('');
}

main().catch((error) => {
  console.error(color.high(`SourceLock: unexpected failure — ${error && error.stack ? error.stack : error}`));
  process.exit(2);
});
