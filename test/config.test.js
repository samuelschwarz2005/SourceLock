'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { ConfigError, createIgnore, parseJsonc, resolveConfig } = require('../lib/config');

const ROOT = path.join(__dirname, '..');

const DEFAULTS = {
  targetDir: './resources',
  extensions: ['.lua', '.js'],
  maxFileBytes: 2 * 1024 * 1024,
  findingsPerRule: 3,
  snippetWidth: 160,
  followSymlinks: false,
  ignorePrivateIps: true,
  WHITELIST: ['node_modules/', 'vendor/'],
  ALLOWED_DOMAINS: ['cfx.re'],
};

const RULE_IDS = ['SL001', 'SL003', 'SL010', 'SL012', 'SL013', 'SL017'];

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sl-config-'));
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

function runScan(cwd, args = []) {
  const argv = [path.join(ROOT, 'scanner.js'), '.', '--json', '--no-color', '--no-trust', ...args];

  try {
    const stdout = execFileSync(process.execPath, argv, {
      cwd,
      encoding: 'utf8',
      timeout: 20000,
      // Never let a test scan post to a real webhook just because the shell has one.
      env: { ...process.env, SOURCELOCK_WEBHOOK_URL: '' },
    });
    return { code: 0, result: JSON.parse(stdout) };
  } catch (error) {
    const stdout = String(error.stdout || '');
    return { code: error.status, result: stdout ? JSON.parse(stdout) : null, stderr: String(error.stderr || '') };
  }
}

/* ---------------------------------------------------------------- JSONC */

test('JSONC parsing keeps // inside strings and strips comments', () => {
  const parsed = parseJsonc(
    `{
      // a line comment
      "url": "https://example.com/a//b",
      /* a block comment */
      "nested": { "ok": true, },
    }`,
    'inline'
  );

  assert.equal(parsed.url, 'https://example.com/a//b');
  assert.equal(parsed.nested.ok, true);
});

test('an unterminated block comment is a config error, not a silent pass', () => {
  assert.throws(() => parseJsonc('{ /* nope', 'inline'), ConfigError);
});

test('a config that is not an object is rejected', () => {
  assert.throws(() => parseJsonc('[]', 'inline'), ConfigError);
});

/* -------------------------------------------------------------- defaults */

test('without a config file the defaults are untouched', () => {
  const resolved = resolve(tmpdir());

  assert.equal(resolved.configPath, null);
  assert.deepEqual(resolved.config.WHITELIST, DEFAULTS.WHITELIST);
  assert.deepEqual(resolved.config.ALLOWED_DOMAINS, DEFAULTS.ALLOWED_DOMAINS);
  assert.equal(resolved.config.findingsPerRule, 3);
  assert.equal(resolved.rules.disabled.size, 0);
});

test('an explicit --config that does not exist fails loudly', () => {
  assert.throws(() => resolve(tmpdir(), { configPath: 'missing.jsonc' }), /config file not found/);
});

/* ------------------------------------------------------------ validation */

test('an unknown setting is rejected with the allowed keys listed', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', JSON.stringify({ whitelst: ['x/'] }));

  assert.throws(() => resolve(dir), (error) => {
    assert.ok(error instanceof ConfigError);
    assert.match(error.message, /unknown setting "whitelst"/);
    assert.match(error.message, /whitelist/);
    return true;
  });
});

test('prototype-polluting keys are rejected', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"__proto__": {"polluted": true}}');

  assert.throws(() => resolve(dir), /not allowed/);
  assert.equal({}.polluted, undefined);
});

test('rules accept off and a new severity, and reject nonsense', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL003": "off", "SL013": "high"}}');

  const resolved = resolve(dir);
  assert.ok(resolved.rules.disabled.has('SL003'));
  assert.equal(resolved.rules.severity.get('SL013'), 'high');

  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL003": "loud"}}');
  assert.throws(() => resolve(dir), /must be "off", "high" or "medium"/);

  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL999": "off"}}');
  assert.throws(() => resolve(dir), /unknown rule SL999/);
});

test('whitelist replaces or extends the defaults on request', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"whitelist": ["custom/"]}');
  assert.deepEqual(resolve(dir).config.WHITELIST, ['node_modules/', 'vendor/', 'custom/']);

  writeFile(dir, '.sourcelock.jsonc', '{"useDefaultWhitelist": false, "whitelist": ["custom/"]}');
  assert.deepEqual(resolve(dir).config.WHITELIST, ['custom/']);
});

test('domains must be bare hostnames and are de-duplicated', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"allowedDomains": ["API.Example.com", "api.example.com"]}');
  const resolved = resolve(dir);

  assert.deepEqual(resolved.config.ALLOWED_DOMAINS, ['cfx.re', 'api.example.com']);

  writeFile(dir, '.sourcelock.jsonc', '{"allowedDomains": ["https://evil.example.com/webhook"]}');
  assert.throws(() => resolve(dir), /bare hostname/);
});

test('out-of-range numbers and bad extensions stop the scan', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"findingsPerRule": 0}');
  assert.throws(() => resolve(dir), /findingsPerRule/);

  writeFile(dir, '.sourcelock.jsonc', '{"extensions": ["lua"]}');
  assert.throws(() => resolve(dir), /must look like/);

  writeFile(dir, '.sourcelock.jsonc', `{"maxFileBytes": ${1024 * 1024 * 1024 * 4}}`);
  assert.throws(() => resolve(dir), /maxFileBytes/);
});

test('an oversized config file is refused instead of parsed', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', `{"snippetWidth": 160, "pad": "${'a'.repeat(300 * 1024)}"}`);

  assert.throws(() => resolve(dir), /over the \d+ byte limit/);
});

/* --------------------------------------------------------------- ignore */

test('ignore patterns follow gitignore-style rules', () => {
  const ignore = createIgnore(
    ['# comment', '', 'build/', '*.min.js', '/root-only.lua', 'deep/**/hidden.lua', '!keep.min.js'].join('\n'),
    'test'
  );

  assert.equal(ignore.match('build', true), true);
  assert.equal(ignore.match('build/script.lua', false), true);
  assert.equal(ignore.match('src/app.min.js', false), true);
  assert.equal(ignore.match('src/keep.min.js', false), false, 'negation re-includes');
  assert.equal(ignore.match('root-only.lua', false), true);
  assert.equal(ignore.match('nested/root-only.lua', false), false, 'leading slash anchors');
  assert.equal(ignore.match('deep/a/b/hidden.lua', false), true);
  assert.equal(ignore.match('deep/hidden.lua', false), true, '** matches zero directories too');
  assert.equal(ignore.match('shallow/hidden.lua', false), false);
  assert.equal(ignore.canPrune, false, 'negation disables directory pruning');
});

test('unsafe ignore patterns are skipped with a warning', () => {
  const ignore = createIgnore(
    ['../secrets', 'C:\\\\Windows', `bad${String.fromCharCode(0)}name`, 'ok/'].join('\n'),
    'test'
  );

  assert.equal(ignore.count, 1);
  assert.equal(ignore.warnings.length, 3);
  assert.equal(ignore.match('../secrets', false), false);
});

test('an explicit --ignore file that is missing is an error', () => {
  assert.throws(() => resolve(tmpdir(), { ignorePath: 'nope.ignore' }), /ignore file not found/);
});

test('ignorePatterns from the config file are honoured', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"ignorePatterns": ["*.bak.lua"]}');
  const resolved = resolve(dir);

  assert.equal(resolved.ignore.match('old.bak.lua', false), true);
});

/* ---------------------------------------------------------- integration */

test('scan ignores a directory listed in .sourcelockignore', () => {
  const dir = tmpdir();
  // "external" is deliberately not in the built-in whitelist: this test is
  // about .sourcelockignore, not the shipped defaults.
  writeFile(dir, '.sourcelockignore', 'external/\n');
  writeFile(dir, 'external/evil.lua', 'loadstring(frombase64("aGk="))()\n');
  writeFile(dir, 'client/main.lua', 'print("hello")\n');

  const { code, result } = runScan(dir);

  assert.equal(code, 0);
  assert.equal(result.findings.length, 0);
  assert.equal(result.stats.ignoredDirs, 1);
  assert.equal(result.config, null, 'no settings file, only an ignore file');
});

test('a rule set to off produces no findings and no failure', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL003": "off"}}');
  writeFile(dir, 'client/main.lua', 'local chunk = load(dynamicCode)\n');

  const { code, result } = runScan(dir);

  assert.equal(code, 0);
  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.rules.disabled, ['SL003']);
});

test('a severity override changes the report and the exit code', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL003": "high"}}');
  writeFile(dir, 'client/main.lua', 'local chunk = load(dynamicCode)\n');

  const { code, result } = runScan(dir);

  assert.equal(code, 1);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.rules.severity.SL003, 'high');
});

test('a broken config aborts the scan with exit code 2 and changes nothing', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL003": "loud"}}');
  writeFile(dir, 'client/main.lua', 'print("fine")\n');

  const { code, stderr } = runScan(dir);

  assert.equal(code, 2);
  assert.match(stderr, /rules\.SL003/);
});

test('--no-config ignores a config file that would otherwise apply', () => {
  const dir = tmpdir();
  writeFile(dir, '.sourcelock.jsonc', '{"rules": {"SL003": "off"}}');
  writeFile(dir, 'client/main.lua', 'local chunk = load(dynamicCode)\n');

  const { code, result } = runScan(dir, ['--no-config']);

  assert.equal(code, 0, 'SL003 is only medium, so the scan still exits 0');
  assert.equal(result.findings.length, 1, 'but the rule ran, because the config was ignored');
  assert.equal(result.config, null);
});
