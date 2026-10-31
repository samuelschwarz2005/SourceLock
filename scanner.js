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
 *   node scanner.js [directory] [--json] [--strict] [--no-color]
 *
 *   directory   Folder to scan. Default: ./resources
 *   --json      Machine-readable output (for CI). Implies --no-color.
 *   --strict    Exit non-zero on medium findings too (default: only high).
 *   --no-color  Disable ANSI colours.
 *
 * Exit codes: 0 = clean, 1 = findings that match the selected policy,
 *             2 = scanner error (bad target, unreadable root, ...).
 *
 * Edit only the CONFIG block below for day-to-day use.
 */

'use strict';

const fsp = require('node:fs/promises');
const path = require('node:path');

/* ==========================================================================
 * CONFIG — edit this block
 * ========================================================================== */

const CONFIG = {
  /** Folder scanned when no directory argument is passed. */
  targetDir: './resources',

  /** Extensions that get scanned. Compared case-insensitively. */
  extensions: ['.lua', '.js', '.html'],

  /** Files larger than this are skipped (protects against minified vendor blobs). */
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
   * Anything else is reported as HIGH.
   */
  ALLOWED_DOMAINS: [
    'cfx.re',
    'fivem.net',
    'github.com',
    'githubusercontent.com',
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

/** Lines that look like outbound HTTP calls; the URL itself is inspected below. */
const HTTP_CALL = /PerformHttpRequest(?:Internal)?\s*\(|\bfetch\s*\(|\bhttp\.request\b/i;
const URL_LITERAL = /https?:\/\/([^/?#\s'"`)\]}>]+)/gi;
const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b(?::\d{2,5})?/g;

/* ==========================================================================
 * CLI / colour helpers
 * ========================================================================== */

const rawArgs = process.argv.slice(2);
const flags = new Set(rawArgs.filter((arg) => arg.startsWith('-')));
const positional = rawArgs.filter((arg) => !arg.startsWith('-'));

if (flags.has('--help') || flags.has('-h')) {
  console.log(
    [
      'SourceLock scanner',
      '',
      'Usage: node scanner.js [directory] [--json] [--strict] [--no-color]',
      '',
      '  directory   Folder to scan (default: ./resources)',
      '  --json      Print JSON instead of the terminal report',
      '  --strict    Also fail on medium-severity findings',
      '  --no-color  Disable ANSI colours',
    ].join('\n')
  );
  process.exit(0);
}

const useColor =
  !flags.has('--no-color') &&
  !flags.has('--json') &&
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
      if (!flags.has('--json')) {
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

async function scanFile(file, stats) {
  let buffer;
  try {
    buffer = await fsp.readFile(file.absolute);
  } catch (error) {
    stats.unreadable += 1;
    return [];
  }

  if (buffer.length > CONFIG.maxFileBytes) {
    stats.skippedLarge += 1;
    return [];
  }

  if (isProbablyBinary(buffer)) {
    stats.skippedBinary += 1;
    return [];
  }

  stats.scanned += 1;

  const findings = [];
  const perRule = new Map();
  const lines = buffer.toString('utf8').split(/\r\n|\n|\r/);

  const record = (lineNumber, line, hit, column) => {
    const seen = perRule.get(hit.ruleId) || 0;
    perRule.set(hit.ruleId, seen + 1);
    if (seen >= CONFIG.findingsPerRule) return;

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

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim().length === 0) continue;

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
    if (total <= CONFIG.findingsPerRule) continue;
    const extra = total - CONFIG.findingsPerRule;
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

async function main() {
  const target = path.resolve(positional[0] || CONFIG.targetDir);

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

  findings.sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line
  );

  const real = findings.filter((finding) => !finding.suppressed);
  const summary = {
    high: real.filter((finding) => finding.severity === 'high').length,
    medium: real.filter((finding) => finding.severity === 'medium').length,
    filesAffected: new Set(real.map((finding) => finding.file)).size,
  };

  const durationMs = Date.now() - started;

  if (flags.has('--json')) {
    console.log(
      JSON.stringify(
        {
          target,
          scannedAt: new Date().toISOString(),
          durationMs,
          stats,
          summary,
          findings,
        },
        null,
        2
      )
    );
  } else {
    printReport({ target, files, stats, findings, summary, durationMs });
  }

  const failed = summary.high > 0 || (flags.has('--strict') && summary.medium > 0);
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
        (stats.skippedLarge ? `, ${stats.skippedLarge} too large` : '') +
        (stats.skippedBinary ? `, ${stats.skippedBinary} binary` : '') +
        (stats.unreadable ? `, ${stats.unreadable} unreadable` : '')
    )
  );
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

    const tag =
      finding.severity === 'high'
        ? color.high('HIGH  ')
        : color.medium('MEDIUM');
    const location = color.dim(`${finding.file}:${finding.line}:${finding.column}`);
    console.log(`    ${tag} ${color.bold(finding.ruleId)}  ${finding.title}`);
    console.log(`           ${location}  ${color.dim(finding.snippet)}`);
  }

  console.log('');
  const parts = [];
  if (summary.high) parts.push(color.high(`${summary.high} high`));
  if (summary.medium) parts.push(color.medium(`${summary.medium} medium`));
  if (parts.length === 0) parts.push(color.ok('0 actionable'));
  console.log(
    `  ${color.bold('Summary:')} ${parts.join(', ')} across ${summary.filesAffected} file(s) — ${durationMs} ms`
  );

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
