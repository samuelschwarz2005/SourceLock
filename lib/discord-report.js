'use strict';

/**
 * SourceLock — Discord reporting.
 *
 * Builds a readable scan report and posts it to a webhook. Uses the global
 * fetch built into Node 18+, so the scanner stays dependency-free: no npm
 * install is needed for --webhook.
 *
 * The report is written for someone who does not know the rule table:
 *   - a headline that says what happened and whether to act,
 *   - one card per finding: file, why it matters, the code, how to trust it,
 *   - a "What to do" section with concrete steps.
 *
 * The webhook URL is a credential: anyone who holds it can post to the
 * channel. It is only accepted from Discord's own hosts, it is never echoed
 * in logs or errors, and mentions are disabled so a hostile file name or
 * snippet cannot ping @everyone.
 */

const EMBED_COLORS = {
  high: 0xd22e2e,
  medium: 0xd9931f,
  clean: 0x2f9e44,
};

const DISCORD_HOSTS = new Set([
  'discord.com',
  'discordapp.com',
  'ptb.discord.com',
  'canary.discord.com',
]);

const WEBHOOK_PATH = /^\/api\/webhooks\/\d{5,}\/[\w-]{20,}$/;

const MAX_FINDINGS_SHOWN = 8;
const MAX_FIELD_CHARS = 1024;
const MAX_EMBED_CHARS = 5200;

/**
 * Plain-English meaning for every rule, so a report can be understood without
 * looking anything up. Keep these short: one line of what it is, one line of
 * why it matters.
 */
const RULE_INFO = {
  SL001: {
    name: 'Runs hidden code from a string',
    why: 'loadstring() executes text built at runtime. Backdoors hide their payload this way.',
  },
  SL002: {
    name: 'Runs hidden code from a string',
    why: 'assert(load(...)) compiles and runs text at runtime, aborting the resource if it fails.',
  },
  SL003: {
    name: 'Loads code at runtime',
    why: 'load() compiles a string while the script runs. Frameworks rarely need this — check what it loads.',
  },
  SL004: {
    name: 'Decodes a base64 payload',
    why: 'frombase64() turns hidden text back into code before running it. Almost never legitimate in a resource.',
  },
  SL005: {
    name: 'Hex-packed strings',
    why: 'Long runs of \\xNN escapes hide readable code from scanners and from you.',
  },
  SL006: {
    name: 'Byte-packed strings',
    why: 'Embedded NUL or decimal byte escapes usually mean an encoded payload.',
  },
  SL007: {
    name: 'Base64 decoding in the UI',
    why: 'Decoding in NUI/JavaScript is a common way to hide injected browser code.',
  },
  SL008: {
    name: 'Runs operating-system commands',
    why: 'os.execute() can run anything on the server host — a resource doing this can take it over.',
  },
  SL009: {
    name: 'Runs a command and reads the output',
    why: 'io.popen() behaves like a remote shell session on the machine running the server.',
  },
  SL010: {
    name: 'Hidden Discord webhook',
    why: 'Backdoors send licence keys, player data or console output to a webhook the author controls.',
  },
  SL011: {
    name: 'HTTP call with a built URL',
    why: 'The destination is assembled at runtime, so nobody can see where the data goes without reading the code.',
  },
  SL012: {
    name: 'HTTP call to an unknown host',
    why: 'Sends data to a domain that is not on your allowlist. Check it is your own API.',
  },
  SL013: {
    name: 'Hard-coded IP address',
    why: 'Talking to a raw IP usually means an unregistered endpoint rather than a known service.',
  },
  SL014: {
    name: 'Compiled Lua bytecode',
    why: 'Bytecode cannot be reviewed by eye: nobody can tell what it does until it runs.',
  },
  SL015: {
    name: 'Binary content in a source file',
    why: 'Source files should be readable text. Embedded binary hides code from review.',
  },
  SL016: {
    name: 'File too large to scan',
    why: 'It was not pattern-scanned at all, so it needs a manual look before you trust it.',
  },
  SL017: {
    name: 'File could not be read',
    why: 'Permissions blocked the scan, which is exactly where a hidden file would sit.',
  },
};

function clean(value, limit = 190) {
  return String(value ?? '')
    .replace(/```/g, '``')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, limit);
}

function plural(count, singular, pluralForm = `${singular}s`) {
  return count === 1 ? singular : pluralForm;
}

/**
 * Returns null when the URL is usable, otherwise a reason.
 * SOURCELOCK_WEBHOOK_ALLOW_LOCAL=1 permits http://127.0.0.1 for local tests only.
 */
function validateWebhookUrl(url) {
  if (typeof url !== 'string' || url.trim() === '') return 'webhook URL is empty';

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return 'webhook URL is malformed';
  }

  const isLocalhost = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost';
  if (isLocalhost && parsed.protocol === 'http:' && process.env.SOURCELOCK_WEBHOOK_ALLOW_LOCAL === '1') {
    return null;
  }

  if (parsed.protocol !== 'https:') return 'webhook URL must use https';
  if (!DISCORD_HOSTS.has(parsed.hostname)) return 'webhook host is not a Discord domain';
  if (!WEBHOOK_PATH.test(parsed.pathname)) return 'webhook path is not /api/webhooks/<id>/<token>';

  return null;
}

/** One readable card per finding. */
function findingField(finding) {
  const info = RULE_INFO[finding.ruleId] || {
    name: clean(finding.title || finding.ruleId, 60),
    why: 'Suspicious pattern — read the line and decide whether it belongs there.',
  };

  const isHigh = finding.severity === 'high';
  const parts = [
    `**${clean(info.name, 80)}**`,
    `**File** \`${clean(finding.file, 80)}:${finding.line}\``,
    `**Why it matters** ${clean(info.why, 240)}`,
  ];

  if (finding.snippet) {
    parts.push(`**Code**\n\`\`\`\n${clean(finding.snippet, 160)}\n\`\`\``);
  }

  if (finding.fingerprint) {
    parts.push(`**If this is yours** \`/trust ${finding.fingerprint}\``);
  }

  return {
    name: `${isHigh ? '🔴' : '🟡'} ${isHigh ? 'HIGH RISK' : 'WARNING'} · ${finding.ruleId}`,
    value: parts.join('\n').slice(0, MAX_FIELD_CHARS),
    inline: false,
  };
}

function buildScanEmbed(result) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const actionable = findings.filter((finding) => !finding.suppressed && !finding.trusted);
  const trusted = findings.filter((finding) => finding.trusted);
  const summary = result.summary || {};
  const stats = result.stats || {};

  const high = summary.high || 0;
  const medium = summary.medium || 0;
  const filesAffected = summary.filesAffected || 0;

  const color = high > 0 ? EMBED_COLORS.high : medium > 0 ? EMBED_COLORS.medium : EMBED_COLORS.clean;

  const title =
    high > 0
      ? `SourceLock scan · ${high} high-risk ${plural(high, 'finding')}`
      : medium > 0
        ? `SourceLock scan · ${medium} ${plural(medium, 'warning')}`
        : 'SourceLock scan · clear';

  let description;
  if (high > 0) {
    description =
      `**Stop before you boot.** ${high} ${plural(high, 'pattern')} used to hide or run code ` +
      `${high === 1 ? 'was' : 'were'} found in ${filesAffected} ${plural(filesAffected, 'file')}. ` +
      'Read each card below; an unrecognised hit usually means the resource is backdoored.';
  } else if (medium > 0) {
    description =
      `No high-risk patterns. ${medium} ${plural(medium, 'warning')} below look unusual but are often legitimate — ` +
      'a quick read is enough.';
  } else {
    description =
      trusted.length > 0
        ? `Nothing new to review. ${trusted.length} known ${plural(trusted.length, 'finding')} ` +
          `${trusted.length === 1 ? 'is' : 'are'} trusted and not counted.`
        : `No suspicious patterns in ${stats.scanned ?? 0} ${plural(stats.scanned ?? 0, 'file')}.`;
  }

  const target = clean(result.target, 100);
  const fields = [
    { name: '📍 Target', value: `\`${target}\``, inline: true },
    { name: '📁 Files scanned', value: `${stats.scanned ?? 0}`, inline: true },
    { name: '⏱️ Duration', value: `${result.durationMs ?? 0} ms`, inline: true },
  ];

  let used = description.length + title.length;
  let shown = 0;

  for (const finding of actionable) {
    if (shown >= MAX_FINDINGS_SHOWN) break;

    const field = findingField(finding);
    const size = field.name.length + field.value.length;
    if (used + size > MAX_EMBED_CHARS) break;

    fields.push(field);
    used += size;
    shown += 1;
  }

  const hidden = actionable.length - shown;
  if (hidden > 0) {
    fields.push({
      name: `➕ ${hidden} more ${plural(hidden, 'finding')}`,
      value: `Only the first ${shown} are shown here. Run \`node scanner.js ${target}\` on the server for the full list.`,
      inline: false,
    });
  }

  if (trusted.length > 0) {
    fields.push({
      name: '✅ Trusted, not counted',
      value:
        `${trusted.length} ${plural(trusted.length, 'finding')} you already approved. ` +
        'Review or remove them with `/trustlist` and `/untrust`.',
      inline: false,
    });
  }

  fields.push({
    name: '👉 What to do',
    value:
      high > 0
        ? '1. Open the file and read the line.\n' +
          '2. Do not recognise it? Remove the resource before booting.\n' +
          '3. It is yours? Trust it with the `/trust` command on its card.\n' +
          '4. Re-run `/scan` to confirm.'
        : medium > 0
          ? 'Warnings are usually fine. Read each line, then trust the ones you recognise so they stop appearing.'
          : 'Nothing to do — keep the scan in your boot routine.',
    inline: false,
  });

  return {
    title,
    color,
    description,
    fields,
    footer: { text: 'SourceLock • red = act now, amber = review, green = clear' },
    timestamp: result.scannedAt || new Date().toISOString(),
  };
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function postJson(url, body, { attempts = 3 } = {}) {
  const invalid = validateWebhookUrl(url);
  if (invalid) throw new Error(invalid);

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (response.status === 429 && attempts > 1) {
    const retryAfter = Number(response.headers.get('retry-after') ?? 1);
    const waitSeconds = Number.isFinite(retryAfter) ? retryAfter : 1;
    await delay(Math.min(30, Math.max(0.5, waitSeconds)) * 1000);
    return postJson(url, body, { attempts: attempts - 1 });
  }

  if (!response.ok) {
    // Never echo the URL: it contains the webhook token.
    throw new Error(`Discord rejected the report (HTTP ${response.status})`);
  }
}

async function postScanReport(url, result) {
  await postJson(url, {
    username: 'SourceLock',
    allowed_mentions: { parse: [] },
    embeds: [buildScanEmbed(result)],
  });
}

module.exports = {
  EMBED_COLORS,
  MAX_FINDINGS_SHOWN,
  RULE_INFO,
  buildScanEmbed,
  postJson,
  postScanReport,
  validateWebhookUrl,
};
