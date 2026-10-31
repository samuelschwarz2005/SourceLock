'use strict';

/**
 * SourceLock — external configuration.
 *
 * Lets a team move the whitelist, rule behaviour and allowlists out of
 * scanner.js so updates no longer conflict with local edits. Zero
 * dependencies: only node:fs and node:path.
 *
 * Three files are understood:
 *
 *   .sourcelock.jsonc   settings (JSON with comments, trailing commas allowed)
 *   .sourcelockignore   gitignore-style patterns for paths never scanned
 *
 * Design rules, because this file decides what gets scanned:
 *   - unknown keys are an error, not a silent no-op: a typo must not quietly
 *     disable a check;
 *   - anything the config cannot understand aborts the scan (exit 2) rather
 *     than falling back to defaults that might hide findings;
 *   - ignore patterns that cannot be trusted (absolute paths, '..', control
 *     characters) are skipped with a warning, never applied;
 *   - every pattern becomes a linear regex: no user text reaches the RegExp
 *     compiler unescaped, so a pathological glob cannot hang the scanner;
 *   - `__proto__`, `constructor` and `prototype` keys are rejected outright.
 */

const fs = require('node:fs');
const path = require('node:path');

const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_IGNORE_BYTES = 256 * 1024;
const MAX_PATTERNS = 2000;
const MAX_PATTERN_CHARS = 200;
const MAX_EXTENSIONS = 20;
const MAX_DOMAINS = 200;

const ALLOWED_KEYS = new Set([
  'targetDir',
  'extensions',
  'maxFileBytes',
  'findingsPerRule',
  'snippetWidth',
  'followSymlinks',
  'useDefaultWhitelist',
  'whitelist',
  'ignorePatterns',
  'ignoreFile',
  'allowedDomains',
  'ignorePrivateIps',
  'rules',
]);

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SEVERITIES = new Set(['off', 'high', 'medium']);

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

/* ==========================================================================
 * Reading and parsing
 * ========================================================================== */

function readText(filePath, limit, label) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new ConfigError(`cannot read ${label} ${filePath}: ${error.code || error.message}`);
  }

  if (!stat.isFile()) throw new ConfigError(`${label} ${filePath} is not a file`);
  if (stat.size > limit) {
    throw new ConfigError(`${label} ${filePath} is ${stat.size} bytes, over the ${limit} byte limit`);
  }

  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    throw new ConfigError(`cannot read ${label} ${filePath}: ${error.code || error.message}`);
  }
}

/**
 * Remove // and /* *\/ comments without touching string contents, so a URL
 * such as "https://api.example.com" survives intact. Unfinished block
 * comments are rejected: a truncated config must not be half-applied.
 */
function stripComments(text) {
  let out = '';
  let index = 0;
  let quote = null;

  while (index < text.length) {
    const char = text[index];

    if (quote) {
      out += char;
      if (char === '\\' && index + 1 < text.length) {
        out += text[index + 1];
        index += 2;
        continue;
      }
      if (char === quote) quote = null;
      index += 1;
      continue;
    }

    if (char === '"') {
      quote = '"';
      out += char;
      index += 1;
      continue;
    }

    if (char === '/' && text[index + 1] === '/') {
      while (index < text.length && text[index] !== '\n') index += 1;
      continue;
    }

    if (char === '/' && text[index + 1] === '*') {
      const end = text.indexOf('*/', index + 2);
      if (end === -1) throw new ConfigError('unterminated /* comment');
      index = end + 2;
      continue;
    }

    out += char;
    index += 1;
  }

  return out;
}

/** Drop commas that directly precede a closing brace or bracket. */
function removeTrailingCommas(text) {
  let out = '';
  let quote = null;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (quote) {
      out += char;
      if (char === '\\' && index + 1 < text.length) {
        out += text[index + 1];
        index += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }

    if (char === '"') {
      quote = '"';
      out += char;
      continue;
    }

    if (char === ',') {
      let lookahead = index + 1;
      while (lookahead < text.length && /\s/.test(text[lookahead])) lookahead += 1;
      const next = text[lookahead];
      if (next === '}' || next === ']') continue;
    }

    out += char;
  }

  return out;
}

function parseJsonc(text, filePath) {
  const withoutBom = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;

  let parsed;
  try {
    parsed = JSON.parse(removeTrailingCommas(stripComments(withoutBom)));
  } catch (error) {
    throw new ConfigError(`${filePath} is not valid JSON: ${error.message}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ConfigError(`${filePath} must contain a JSON object`);
  }

  return parsed;
}

/* ==========================================================================
 * Validation helpers
 * ========================================================================== */

const MAX_STRING = 4096;

function isPlainString(value, max = MAX_STRING) {
  return typeof value === 'string' && value.length <= max;
}

function hasControlChars(value) {
  return /[\u0000-\u001f\u007f]/.test(value);
}

function integer(value, min, max, label, filePath) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ConfigError(
      `${filePath}: ${label} must be an integer between ${min} and ${max} (got ${JSON.stringify(value)})`
    );
  }
  return value;
}

function stringList(value, label, filePath, { max = MAX_PATTERNS, maxChars = MAX_PATTERN_CHARS } = {}) {
  if (!Array.isArray(value)) throw new ConfigError(`${filePath}: ${label} must be an array of strings`);
  if (value.length > max) throw new ConfigError(`${filePath}: ${label} has ${value.length} entries, the limit is ${max}`);

  return value.map((entry) => {
    if (!isPlainString(entry, maxChars) || entry.trim() === '') {
      throw new ConfigError(`${filePath}: ${label} entries must be non-empty strings of at most ${maxChars} characters`);
    }
    if (hasControlChars(entry)) {
      throw new ConfigError(`${filePath}: ${label} entry contains control characters`);
    }
    return entry;
  });
}

function normalizeDomain(entry, filePath) {
  const host = String(entry).trim().toLowerCase().replace(/\.$/, '');
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(host)) {
    throw new ConfigError(
      `${filePath}: allowedDomains entry ${JSON.stringify(entry)} is not a bare hostname (no scheme, port or path)`
    );
  }
  if (host.length > 253) throw new ConfigError(`${filePath}: allowedDomains entry is too long`);
  return host;
}

/** Normalise an extension list and refuse anything that is not ".ext". */
function normalizeExtensions(value, filePath) {
  const list = stringList(value, 'extensions', filePath, { max: MAX_EXTENSIONS, maxChars: 16 });
  return list.map((entry) => {
    const ext = entry.trim().toLowerCase();
    if (!/^\.[a-z0-9]{1,12}$/.test(ext)) {
      throw new ConfigError(`${filePath}: extension ${JSON.stringify(entry)} must look like ".lua"`);
    }
    return ext;
  });
}

function normalizeRules(value, filePath, ruleIds) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ConfigError(`${filePath}: rules must be an object of { "SL003": "off" | "high" | "medium" }`);
  }

  const known = new Set(ruleIds);
  const disabled = new Set();
  const severity = new Map();

  for (const key of Object.keys(value)) {
    if (FORBIDDEN_KEYS.has(key)) throw new ConfigError(`${filePath}: rules may not contain the key ${key}`);

    const id = key.toUpperCase();
    if (!known.has(id)) {
      throw new ConfigError(`${filePath}: unknown rule ${key} in rules (known: ${ruleIds.join(', ')})`);
    }

    const setting = value[key];
    if (typeof setting !== 'string' || !SEVERITIES.has(setting.toLowerCase())) {
      throw new ConfigError(`${filePath}: rules.${key} must be "off", "high" or "medium"`);
    }

    const level = setting.toLowerCase();
    if (level === 'off') disabled.add(id);
    else severity.set(id, level);
  }

  return { disabled, severity };
}

/* ==========================================================================
 * Ignore patterns
 * ========================================================================== */

/**
 * Match one path segment against a `*`/`?` glob.
 *
 * Deliberately not a regular expression: the greedy two-pointer algorithm is
 * linear in the length of the input, so a pattern full of stars cannot be
 * turned into a backtracking bomb. `*a*a*a*a*a` on a long path stays cheap.
 */
function matchSegment(pattern, text) {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;

  const source = pattern.toLowerCase();
  const target = text.toLowerCase();

  while (t < target.length) {
    if (p < source.length && (source[p] === '?' || source[p] === target[t])) {
      p += 1;
      t += 1;
    } else if (p < source.length && source[p] === '*') {
      star = p;
      p += 1;
      mark = t;
    } else if (star !== -1) {
      p = star + 1;
      mark += 1;
      t = mark;
    } else {
      return false;
    }
  }

  while (p < source.length && source[p] === '*') p += 1;
  return p === source.length;
}

/**
 * Match path segments against pattern segments, where `**` spans any number
 * of segments (including none). Dynamic programming over segments keeps this
 * O(pattern × path) with no backtracking.
 */
function matchSegments(patternSegments, pathSegments) {
  const width = pathSegments.length;
  let previous = new Array(width + 1).fill(false);
  // The empty pattern matches exactly the empty suffix of the path.
  previous[width] = true;

  for (let index = patternSegments.length - 1; index >= 0; index -= 1) {
    const segment = patternSegments[index];
    const current = new Array(width + 1).fill(false);

    if (segment === '**') {
      current[width] = previous[width];
      for (let column = width - 1; column >= 0; column -= 1) {
        current[column] = previous[column] || current[column + 1];
      }
    } else {
      for (let column = 0; column < width; column += 1) {
        current[column] = previous[column + 1] && matchSegment(segment, pathSegments[column]);
      }
    }

    previous = current;
  }

  return previous[0];
}

/**
 * Validate one ignore line. Returns null for entries that must be skipped,
 * and throws ConfigError for entries that are dangerous.
 */
function buildIgnoreRule(raw, source) {
  let pattern = String(raw).trim();
  if (pattern === '' || pattern.startsWith('#')) return null;

  let negate = false;
  if (pattern.startsWith('!')) {
    negate = true;
    pattern = pattern.slice(1);
  }

  // Trailing spaces are ignored by git; keep one escape hatch: "\ " keeps it.
  if (pattern.endsWith('\\ ')) pattern = `${pattern.slice(0, -2)} `;
  else pattern = pattern.replace(/\s+$/, '');

  if (pattern === '') return null;

  let dirOnly = false;
  if (pattern.endsWith('/')) {
    dirOnly = true;
    pattern = pattern.slice(0, -1);
  }

  let anchored = false;
  if (pattern.startsWith('/')) {
    anchored = true;
    pattern = pattern.slice(1);
  }

  pattern = pattern.replace(/\\/g, '/');
  if (pattern.length > MAX_PATTERN_CHARS) {
    throw new ConfigError(`${source}: ignore pattern is longer than ${MAX_PATTERN_CHARS} characters`);
  }
  if (hasControlChars(pattern)) {
    throw new ConfigError(`${source}: ignore pattern contains control characters`);
  }
  if (/^[a-zA-Z]:/.test(pattern)) {
    throw new ConfigError(`${source}: ignore pattern ${JSON.stringify(pattern)} looks like an absolute path`);
  }

  const segments = pattern.split('/').filter((segment) => segment !== '' && segment !== '.');
  if (segments.includes('..')) {
    throw new ConfigError(`${source}: ignore pattern ${JSON.stringify(pattern)} may not contain '..'`);
  }
  if (segments.length === 0) return null;

  const normalised = segments.join('/');
  const hasSlash = normalised.includes('/');
  const patternSegments = normalised.split('/');

  return {
    negate,
    dirOnly,
    anchored: anchored || hasSlash,
    segments: patternSegments,
    pattern: normalised,
    test(relativePath, base) {
      const pathSegments = (this.anchored ? relativePath : base).split('/');
      return matchSegments(this.segments, pathSegments);
    },
  };
}

function createIgnore(rawText, sourcePath) {
  const rules = [];
  const warnings = [];

  if (typeof rawText === 'string') {
    // A BOM would otherwise become part of the first pattern and silently stop
    // it matching. Windows editors add one routinely.
    const text = rawText.charCodeAt(0) === 0xfeff ? rawText.slice(1) : rawText;
    const lines = text.split(/\r\n|\r|\n/);
    if (lines.length > MAX_PATTERNS * 2) {
      throw new ConfigError(`${sourcePath}: ignore file has ${lines.length} lines, the limit is ${MAX_PATTERNS * 2}`);
    }

    for (const line of lines) {
      try {
        const rule = buildIgnoreRule(line, sourcePath);
        if (rule) rules.push(rule);
      } catch (error) {
        // An unusable pattern is skipped loudly: applying it could hide files,
        // and aborting the whole scan over one typo is worse than warning.
        warnings.push(error.message);
      }
    }
  }

  if (rules.filter((rule) => !rule.negate).length > MAX_PATTERNS) {
    throw new ConfigError(`${sourcePath}: more than ${MAX_PATTERNS} ignore patterns`);
  }

  const hasNegation = rules.some((rule) => rule.negate);

  return {
    rules,
    warnings,
    sourcePath: sourcePath || null,
    get count() {
      return rules.length;
    },
    /**
     * True when the relative path is ignored. Rules are evaluated in order and
     * the last match wins, so a later `!pattern` can re-include a file.
     */
    match(relativePath, isDirectory) {
      if (rules.length === 0) return false;

      const rel = String(relativePath).replace(/\\/g, '/');
      const parts = rel.split('/');
      const candidates = [];

      for (let index = 1; index <= parts.length; index += 1) {
        const candidate = parts.slice(0, index).join('/');
        candidates.push({
          path: candidate,
          base: parts[index - 1],
          isDirectory: index < parts.length ? true : Boolean(isDirectory),
        });
      }

      let ignored = false;

      for (const rule of rules) {
        let matched = false;
        for (const candidate of candidates) {
          if (rule.dirOnly && !candidate.isDirectory) continue;
          if (rule.test(candidate.path, candidate.base)) {
            matched = true;
            break;
          }
        }
        if (matched) ignored = !rule.negate;
      }

      return ignored;
    },
    /**
     * Pruning a directory is only safe when no negation exists: without it,
     * a re-included file inside a pruned folder would never be reached.
     */
    canPrune: !hasNegation,
  };
}

/* ==========================================================================
 * Config resolution
 * ========================================================================== */

function validateConfig(raw, filePath, ruleIds) {
  for (const key of Object.keys(raw)) {
    if (FORBIDDEN_KEYS.has(key)) throw new ConfigError(`${filePath}: the key ${key} is not allowed`);
    if (!ALLOWED_KEYS.has(key)) {
      throw new ConfigError(
        `${filePath}: unknown setting ${JSON.stringify(key)} — allowed keys: ${[...ALLOWED_KEYS].sort().join(', ')}`
      );
    }
  }

  const settings = {};

  if ('targetDir' in raw) {
    if (!isPlainString(raw.targetDir, 1024) || raw.targetDir.trim() === '') {
      throw new ConfigError(`${filePath}: targetDir must be a non-empty string`);
    }
    settings.targetDir = raw.targetDir.trim();
  }

  if ('extensions' in raw) settings.extensions = normalizeExtensions(raw.extensions, filePath);

  if ('maxFileBytes' in raw) {
    settings.maxFileBytes = integer(raw.maxFileBytes, 1024, 1024 * 1024 * 1024, 'maxFileBytes', filePath);
  }

  if ('findingsPerRule' in raw) {
    settings.findingsPerRule = integer(raw.findingsPerRule, 1, 1000, 'findingsPerRule', filePath);
  }

  if ('snippetWidth' in raw) {
    settings.snippetWidth = integer(raw.snippetWidth, 40, 2000, 'snippetWidth', filePath);
  }

  if ('followSymlinks' in raw) {
    if (typeof raw.followSymlinks !== 'boolean') throw new ConfigError(`${filePath}: followSymlinks must be true or false`);
    settings.followSymlinks = raw.followSymlinks;
  }

  if ('ignorePrivateIps' in raw) {
    if (typeof raw.ignorePrivateIps !== 'boolean') {
      throw new ConfigError(`${filePath}: ignorePrivateIps must be true or false`);
    }
    settings.ignorePrivateIps = raw.ignorePrivateIps;
  }

  if ('useDefaultWhitelist' in raw) {
    if (typeof raw.useDefaultWhitelist !== 'boolean') {
      throw new ConfigError(`${filePath}: useDefaultWhitelist must be true or false`);
    }
    settings.useDefaultWhitelist = raw.useDefaultWhitelist;
  }

  if ('whitelist' in raw) {
    settings.whitelist = stringList(raw.whitelist, 'whitelist', filePath);

    // The whitelist matcher turns "*" into ".*", so a pattern full of stars
    // can backtrack badly on a long path. Real entries never need many.
    for (const entry of settings.whitelist) {
      const stars = (entry.match(/\*/g) || []).length;
      if (stars > 4) {
        throw new ConfigError(
          `${filePath}: whitelist entry ${JSON.stringify(entry)} has ${stars} wildcards, the limit is 4`
        );
      }
    }
  }

  if ('ignorePatterns' in raw) {
    settings.ignorePatterns = stringList(raw.ignorePatterns, 'ignorePatterns', filePath);
  }

  if ('ignoreFile' in raw) {
    if (!isPlainString(raw.ignoreFile, 1024) || raw.ignoreFile.trim() === '') {
      throw new ConfigError(`${filePath}: ignoreFile must be a non-empty path`);
    }
    settings.ignoreFile = raw.ignoreFile.trim();
  }

  if ('allowedDomains' in raw) {
    const list = stringList(raw.allowedDomains, 'allowedDomains', filePath, {
      max: MAX_DOMAINS,
      maxChars: 253,
    });
    settings.allowedDomains = list.map((entry) => normalizeDomain(entry, filePath));
  }

  if ('rules' in raw) settings.rules = normalizeRules(raw.rules, filePath, ruleIds);

  return settings;
}

/**
 * Load a config file if one exists, merge it over the built-in defaults, and
 * return everything the scanner needs. Throws ConfigError on bad input.
 */
function resolveConfig({ cwd = process.cwd(), configPath = null, ignorePath = null, useConfig = true, defaults, ruleIds = [] }) {
  const warnings = [];
  let settings = {};
  let resolvedConfigPath = null;
  let configDir = cwd;

  if (useConfig) {
    const candidate = configPath ? path.resolve(cwd, configPath) : path.resolve(cwd, '.sourcelock.jsonc');
    const text = readText(candidate, MAX_CONFIG_BYTES, 'config file');

    if (text === null) {
      if (configPath) throw new ConfigError(`config file not found: ${candidate}`);
    } else {
      resolvedConfigPath = candidate;
      configDir = path.dirname(candidate);
      settings = validateConfig(parseJsonc(text, candidate), candidate, ruleIds);
    }
  } else if (configPath) {
    throw new ConfigError('--config and --no-config cannot be used together');
  }

  const baseWhitelist = settings.useDefaultWhitelist === false ? [] : [...defaults.WHITELIST];
  const whitelist = [...baseWhitelist, ...(settings.whitelist || [])];

  const domains = [...defaults.ALLOWED_DOMAINS];
  for (const domain of settings.allowedDomains || []) {
    if (!domains.some((existing) => existing.toLowerCase() === domain)) domains.push(domain);
  }

  const config = {
    ...defaults,
    ...settings,
    WHITELIST: whitelist,
    ALLOWED_DOMAINS: domains,
  };

  if (settings.targetDir) {
    config.targetDir = path.resolve(configDir, settings.targetDir);
  }

  const rules = settings.rules || { disabled: new Set(), severity: new Map() };

  // Ignore file: explicit path wins, otherwise next to the config file, and
  // the preset patterns from the config are applied first so a later `!` there
  // can re-include something the file ignores.
  const ignoreLines = [];
  let ignoreSource = null;

  if (useConfig) {
    const ignoreCandidate = ignorePath
      ? path.resolve(cwd, ignorePath)
      : settings.ignoreFile
        ? path.resolve(configDir, settings.ignoreFile)
        : path.resolve(configDir, '.sourcelockignore');

    const ignoreText = readText(ignoreCandidate, MAX_IGNORE_BYTES, 'ignore file');
    if (ignoreText !== null) {
      ignoreLines.push(ignoreText);
      ignoreSource = ignoreCandidate;
    } else if (ignorePath) {
      throw new ConfigError(`ignore file not found: ${ignoreCandidate}`);
    }
  }

  if (settings.ignorePatterns && settings.ignorePatterns.length > 0) {
    ignoreLines.push(settings.ignorePatterns.join('\n'));
    ignoreSource = ignoreSource || resolvedConfigPath || '<config>';
  }

  const ignore = createIgnore(ignoreLines.join('\n'), ignoreSource);
  warnings.push(...ignore.warnings);

  return { config, rules, ignore, configPath: resolvedConfigPath, warnings };
}

module.exports = {
  ConfigError,
  MAX_IGNORE_BYTES,
  MAX_PATTERN_CHARS,
  MAX_PATTERNS,
  createIgnore,
  parseJsonc,
  resolveConfig,
  stripComments,
};
