'use strict';

/**
 * SourceLock — trust store.
 *
 * A trust entry accepts ONE specific finding, not a whole file or rule.
 * The fingerprint is derived from file + rule + normalised snippet, so:
 *   - editing that line produces a new fingerprint (the trust stops applying),
 *   - moving the line elsewhere keeps the fingerprint (line numbers excluded),
 *   - a different rule hitting the same text is still reported.
 *
 * Zero dependencies: the scanner and the bot both require this file.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_TRUST_FILE = './sourcelock-trust.json';
const FINGERPRINT = /^[0-9a-f]{16}$/;

function normalizeSnippet(value) {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

/** Stable 16-hex-character identity for a single finding. */
function fingerprintFinding(finding) {
  const material = [finding.file, finding.ruleId, normalizeSnippet(finding.snippet)].join('|');
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, 16);
}

function emptyTrust() {
  return { version: 1, entries: [] };
}

/**
 * Read the trust list. A missing file is an empty list; anything malformed
 * throws so callers can decide — the scanner ignores it and reports everything
 * (fail closed), the bot refuses to overwrite a file it cannot understand.
 */
function loadTrust(filePath = DEFAULT_TRUST_FILE) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return emptyTrust();
    throw new Error(`cannot read trust file ${filePath}: ${error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`trust file ${filePath} is not valid JSON`);
  }

  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.entries)) {
    throw new Error(`trust file ${filePath} has an unexpected shape`);
  }

  const entries = parsed.entries
    .filter((entry) => entry && FINGERPRINT.test(String(entry.fingerprint || '').toLowerCase()))
    .map((entry) => ({
      fingerprint: String(entry.fingerprint).toLowerCase(),
      note: String(entry.note || ''),
      addedBy: String(entry.addedBy || ''),
      addedAt: String(entry.addedAt || ''),
    }));

  return { version: 1, entries };
}

function isTrusted(trust, finding) {
  const fingerprint = String(finding.fingerprint || fingerprintFinding(finding)).toLowerCase();
  return trust.entries.some((entry) => entry.fingerprint === fingerprint);
}

/** Add or update an entry. Returns whether it was new. */
function addTrust(trust, entry) {
  const fingerprint = String(entry.fingerprint || '').toLowerCase();
  if (!FINGERPRINT.test(fingerprint)) {
    throw new Error('fingerprint must be 16 hex characters, as printed in a scan report');
  }

  const existing = trust.entries.find((item) => item.fingerprint === fingerprint);
  if (existing) {
    if (entry.note !== undefined) existing.note = String(entry.note);
    if (entry.addedBy !== undefined) existing.addedBy = String(entry.addedBy);
    if (entry.addedAt !== undefined) existing.addedAt = String(entry.addedAt);
    return { trust, added: false };
  }

  trust.entries.push({
    fingerprint,
    note: String(entry.note || ''),
    addedBy: String(entry.addedBy || ''),
    addedAt: String(entry.addedAt || new Date().toISOString()),
  });

  return { trust, added: true };
}

function removeTrust(trust, fingerprint) {
  const target = String(fingerprint || '').toLowerCase();
  const before = trust.entries.length;
  trust.entries = trust.entries.filter((entry) => entry.fingerprint !== target);
  return before !== trust.entries.length;
}

/** Atomic write: a crash mid-save must never leave a half-written trust list. */
function saveTrust(filePath, trust) {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });

  const temporary = `${resolved}.${process.pid}.tmp`;
  const body = `${JSON.stringify({ version: 1, entries: trust.entries }, null, 2)}\n`;
  fs.writeFileSync(temporary, body, 'utf8');
  fs.renameSync(temporary, resolved);
}

module.exports = {
  DEFAULT_TRUST_FILE,
  FINGERPRINT,
  addTrust,
  emptyTrust,
  fingerprintFinding,
  isTrusted,
  loadTrust,
  normalizeSnippet,
  removeTrust,
  saveTrust,
};
