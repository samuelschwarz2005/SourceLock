#!/usr/bin/env node
'use strict';

/**
 * SourceLock — report preview.
 *
 * Shows exactly what the scanner posts to a Discord webhook, without needing a
 * webhook, a Discord server or a real scan. It calls the same buildScanEmbed()
 * the scanner uses, so what you see here is byte-for-byte the report body.
 *
 *   node tools/preview-report.js              print three sample reports
 *   node tools/preview-report.js --send URL   post them to a webhook
 *   node tools/preview-report.js --send       post to $SOURCELOCK_WEBHOOK_URL
 *
 * Sending is opt-in and prints the URL's host only, never the token.
 */

const { buildScanEmbed, postScanReport, validateWebhookUrl } = require('../lib/discord-report');

const found = (ruleId, severity, file, line, snippet, fingerprint) => ({
  ruleId,
  severity,
  file,
  line,
  column: 3,
  snippet,
  fingerprint,
  title: ruleId,
});

const scenarios = [
  {
    name: 'two high-risk findings',
    result: {
      target: 'resources/banking',
      scannedAt: '2026-10-31T12:00:00.000Z',
      durationMs: 118,
      stats: { scanned: 41 },
      summary: { high: 2, medium: 1, filesAffected: 2 },
      findings: [
        found(
          'SL001',
          'high',
          'client/main.lua',
          42,
          'loadstring(frombase64("bG9jYWwgYWM9J2FjJy..."))()',
          '9f2c71ab4de80531',
        ),
        found(
          'SL010',
          'high',
          'server/licence.lua',
          17,
          'PerformHttpRequest("https://discord.com/api/webhooks/123456789/hidden", cb)',
          '4b8e0d1c7a2f9365',
        ),
        found(
          'SL003',
          'medium',
          'client/menu.lua',
          88,
          'local chunk = load(menuSource, "menu", "t")',
          'c17a5e9042bd6f88',
        ),
      ],
    },
  },
  {
    name: 'warnings only',
    result: {
      target: 'resources/inventory',
      scannedAt: '2026-10-31T12:05:00.000Z',
      durationMs: 96,
      stats: { scanned: 27 },
      summary: { high: 0, medium: 2, filesAffected: 2 },
      findings: [
        found('SL011', 'medium', 'server/api.lua', 30, 'PerformHttpRequest(endpoint, cb, "POST")', 'aa31be7c0d4f1928'),
        found('SL013', 'medium', 'client/sync.lua', 64, 'local host = "203.0.113.42"', 'eed40c6ab9157f23'),
      ],
    },
  },
  {
    name: 'clean, with trust',
    result: {
      target: 'resources/garage',
      scannedAt: '2026-10-31T12:10:00.000Z',
      durationMs: 54,
      stats: { scanned: 19 },
      summary: { high: 0, medium: 0, filesAffected: 0 },
      findings: [
        { ...found('SL003', 'medium', 'client/garage.lua', 51, 'load(cache, "chunk")', 'b0a4d9e2f6713c55'), trusted: true },
      ],
    },
  },
];

const COLOUR_SQUARE = { 0xd22e2e: '🟥', 0xd9931f: '🟧', 0x2f9e44: '🟩' };
const RULE_LINE = '─'.repeat(64);

function render(name, result) {
  const embed = buildScanEmbed(result);
  const out = [];

  out.push(`┌─ SourceLock  ·  sample report: ${name}`);
  out.push(`│ ${COLOUR_SQUARE[embed.color] || '⬜'} colour bar  #${embed.color.toString(16).padStart(6, '0')}`);
  out.push(`│ **${embed.title}**`);
  out.push('│');
  for (const line of embed.description.split('\n')) out.push(`│ ${line}`);
  out.push('│');

  let inlineRow = [];
  const flush = () => {
    if (inlineRow.length) {
      out.push(`│ ${inlineRow.join('   │   ')}`);
      inlineRow = [];
    }
  };

  for (const field of embed.fields) {
    if (field.inline) {
      inlineRow.push(`${field.name}  ${field.value.replace(/\n/g, ' ')}`);
      continue;
    }
    flush();
    out.push(`│ ${RULE_LINE}`);
    out.push(`│ ${field.name}`);
    for (const line of field.value.split('\n')) out.push(`│   ${line}`);
  }
  flush();

  out.push('│');
  out.push(`│ ${embed.footer.text}`);
  out.push(`└─ timestamp ${embed.timestamp}`);
  return out.join('\n');
}

async function main() {
  const argv = process.argv.slice(2);
  const sendAt = argv.indexOf('--send');
  const rawUrl = sendAt === -1 ? null : argv[sendAt + 1] && !argv[sendAt + 1].startsWith('--') ? argv[sendAt + 1] : process.env.SOURCELOCK_WEBHOOK_URL;
  const url = rawUrl || null;

  for (const { name, result } of scenarios) {
    process.stdout.write(`${render(name, account(result))}\n\n`);
  }

  if (sendAt === -1) {
    process.stdout.write('Preview only — nothing was sent.\n');
    process.stdout.write('To deliver these to a channel: node tools/preview-report.js --send <webhook-url>\n');
    return;
  }

  if (!url) {
    fail('No webhook URL: pass it after --send or set SOURCELOCK_WEBHOOK_URL.');
  }

  const invalid = validateWebhookUrl(url);
  if (invalid) fail(`${invalid} (nothing was sent)`);

  process.stdout.write(`Sending 3 sample reports to ${new URL(url).host} …\n`);
  for (const { name, result } of scenarios) {
    await postScanReport(url, account(result));
    process.stdout.write(`  sent: ${name}\n`);
  }
  process.stdout.write('Done. Check the channel.\n');
}

/** Summary counters are what the scanner would report for these findings. */
function account(result) {
  const live = result.findings.filter((f) => !f.trusted && !f.suppressed);
  return {
    ...result,
    summary: {
      high: live.filter((f) => f.severity === 'high').length,
      medium: live.filter((f) => f.severity === 'medium').length,
      filesAffected: new Set(live.map((f) => f.file)).size,
    },
  };
}

function fail(message) {
  process.stderr.write(`preview-report: ${message}\n`);
  process.exit(2);
}

main().catch((error) => fail(error.message));
