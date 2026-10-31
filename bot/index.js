'use strict';

/**
 * SourceLock — Discord bot.
 *
 * Incoming webhooks can only be posted TO, so running scans and managing trust
 * needs a real bot. Commands:
 *
 *   /scan [path]                 run scanner.js and post the report
 *   /trust <fingerprint> [note]  accept one specific finding
 *   /untrust <fingerprint>       remove a trust entry
 *   /trustlist                   list trusted fingerprints
 *
 * Security posture:
 *   - fails closed: with no DISCORD_ALLOWED_ROLE_IDS / DISCORD_ALLOWED_USER_IDS
 *     configured, the bot refuses to start;
 *   - /scan is confined to SCAN_ROOT, so a command cannot read arbitrary folders;
 *   - the bot never prints its token, and scanner output is size-capped;
 *   - trust writes are atomic, so a crash cannot corrupt the trust list.
 */

const path = require('node:path');
const { execFile } = require('node:child_process');
const {
  ApplicationCommandOptionType,
  Client,
  Events,
  GatewayIntentBits,
  MessageFlags,
} = require('discord.js');

const { addTrust, loadTrust, removeTrust, saveTrust } = require('../lib/trust');
const { buildScanEmbed } = require('../lib/discord-report');

const ROOT = path.join(__dirname, '..');

function splitIds(value) {
  return String(value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => /^\d{5,}$/.test(entry));
}

const CONFIG = {
  token: String(process.env.DISCORD_TOKEN || '').trim(),
  guildId: String(process.env.DISCORD_GUILD_ID || '').trim(),
  scanRoot: path.resolve(process.env.SCAN_ROOT || path.join(ROOT, 'resources')),
  scanner: path.join(ROOT, 'scanner.js'),
  trustFile: path.resolve(process.env.SOURCELOCK_TRUST_FILE || path.join(ROOT, 'sourcelock-trust.json')),
  allowedRoles: splitIds(process.env.DISCORD_ALLOWED_ROLE_IDS),
  allowedUsers: splitIds(process.env.DISCORD_ALLOWED_USER_IDS),
  timeoutMs: 120000,
};

function isAuthorized(member) {
  if (!member) return false;
  if (CONFIG.allowedRoles.length === 0 && CONFIG.allowedUsers.length === 0) return false;
  if (CONFIG.allowedUsers.includes(member.id)) return true;
  return CONFIG.allowedRoles.some((roleId) => member.roles.cache.has(roleId));
}

/** Keep scan targets inside SCAN_ROOT — no '..', no arbitrary absolute paths. */
function resolveTarget(input) {
  const root = path.resolve(CONFIG.scanRoot);
  const requested = input ? path.resolve(root, input) : root;

  if (requested !== root && !requested.startsWith(root + path.sep)) {
    throw new Error('path is outside SCAN_ROOT');
  }

  return requested;
}

function runScanner(target) {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [CONFIG.scanner, target, '--json', '--no-color', '--trust-file', CONFIG.trustFile],
      { timeout: CONFIG.timeoutMs, maxBuffer: 64 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (!stdout) {
          const message = String(stderr || error?.message || 'scanner produced no output');
          reject(new Error(message.trim().slice(0, 300)));
          return;
        }

        try {
          // Exit code 1 means "findings", not failure: stdout still holds the report.
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error('could not parse scanner output'));
        }
      }
    );
  });
}

const COMMANDS = [
  {
    name: 'scan',
    description: 'Run a SourceLock scan and post the findings',
    options: [
      {
        type: ApplicationCommandOptionType.String,
        name: 'path',
        description: 'Sub-path inside SCAN_ROOT (default: the root itself)',
        required: false,
      },
    ],
  },
  {
    name: 'trust',
    description: 'Accept one specific finding so it stops blocking scans',
    options: [
      {
        type: ApplicationCommandOptionType.String,
        name: 'fingerprint',
        description: '16-hex fingerprint from a scan report',
        required: true,
      },
      {
        type: ApplicationCommandOptionType.String,
        name: 'note',
        description: 'Why this finding is safe',
        required: false,
      },
    ],
  },
  {
    name: 'untrust',
    description: 'Remove a trust entry by fingerprint',
    options: [
      {
        type: ApplicationCommandOptionType.String,
        name: 'fingerprint',
        description: '16-hex fingerprint',
        required: true,
      },
    ],
  },
  {
    name: 'trustlist',
    description: 'List trusted fingerprints',
  },
];

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

function readTrust() {
  try {
    return loadTrust(CONFIG.trustFile);
  } catch (error) {
    throw new Error(`trust file unusable: ${error.message}`);
  }
}

function readFingerprint(interaction) {
  const value = String(interaction.options.getString('fingerprint', true) || '').trim().toLowerCase();
  if (!/^[0-9a-f]{16}$/.test(value)) {
    throw new Error('fingerprint must be the 16 hex characters shown after # in a scan report');
  }
  return value;
}

async function handleScan(interaction) {
  await interaction.deferReply();

  const target = resolveTarget(interaction.options.getString('path'));
  const result = await runScanner(target);

  await interaction.editReply({ embeds: [buildScanEmbed(result)] });
}

async function handleTrust(interaction) {
  const fingerprint = readFingerprint(interaction);
  const trust = readTrust();

  const { added } = addTrust(trust, {
    fingerprint,
    note: interaction.options.getString('note') || '',
    addedBy: `${interaction.user.tag} (${interaction.user.id})`,
    addedAt: new Date().toISOString(),
  });

  saveTrust(CONFIG.trustFile, trust);

  await interaction.reply({
    content: `${added ? 'Trusted' : 'Updated'} \`${fingerprint}\`. Future scans will ignore that finding.`,
    flags: MessageFlags.Ephemeral,
  });
}

async function handleUntrust(interaction) {
  const fingerprint = readFingerprint(interaction);
  const trust = readTrust();

  if (!removeTrust(trust, fingerprint)) {
    await interaction.reply({
      content: `No trust entry for \`${fingerprint}\`.`,
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  saveTrust(CONFIG.trustFile, trust);
  await interaction.reply({
    content: `Removed \`${fingerprint}\`.`,
    flags: MessageFlags.Ephemeral,
  });
}

async function handleTrustlist(interaction) {
  const trust = readTrust();

  if (trust.entries.length === 0) {
    await interaction.reply({ content: 'No findings are trusted.', flags: MessageFlags.Ephemeral });
    return;
  }

  const lines = trust.entries
    .slice(-25)
    .map((entry) => `\`${entry.fingerprint}\`${entry.note ? ` — ${entry.note.slice(0, 80)}` : ''}`);

  const header = `Trusted findings (${trust.entries.length}):`;
  await interaction.reply({
    content: `${header}\n${lines.join('\n')}`.slice(0, 1900),
    flags: MessageFlags.Ephemeral,
  });
}

client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isChatInputCommand()) return;

  if (!isAuthorized(interaction.member)) {
    await interaction.reply({
      content: 'You are not authorised to use SourceLock.',
      flags: MessageFlags.Ephemeral,
    });
    return;
  }

  try {
    if (interaction.commandName === 'scan') return await handleScan(interaction);
    if (interaction.commandName === 'trust') return await handleTrust(interaction);
    if (interaction.commandName === 'untrust') return await handleUntrust(interaction);
    if (interaction.commandName === 'trustlist') return await handleTrustlist(interaction);

    await interaction.reply({ content: 'Unknown command.', flags: MessageFlags.Ephemeral });
  } catch (error) {
    const message = String(error?.message || 'unexpected error').slice(0, 500);

    if (interaction.deferred || interaction.replied) {
      await interaction.editReply({ content: `Error: ${message}` });
    } else {
      await interaction.reply({ content: `Error: ${message}`, flags: MessageFlags.Ephemeral });
    }
  }
});

client.once(Events.ClientReady, async (ready) => {
  try {
    await ready.application.commands.set(COMMANDS, CONFIG.guildId || undefined);
    const scope = CONFIG.guildId ? `guild ${CONFIG.guildId}` : 'globally (may take up to an hour)';
    console.log(`SourceLock bot ready as ${ready.user.tag}; commands registered ${scope}`);
  } catch (error) {
    console.error(`command registration failed: ${error.message}`);
  }
});

// Exported so the guards below can be exercised without connecting to Discord.
module.exports = { CONFIG, COMMANDS, isAuthorized, resolveTarget, runScanner };

if (require.main === module) {
  if (!CONFIG.token) {
    console.error('DISCORD_TOKEN is not set. Export it in the environment that runs the bot.');
    process.exit(2);
  }

  if (CONFIG.allowedRoles.length === 0 && CONFIG.allowedUsers.length === 0) {
    console.error('Refusing to start: set DISCORD_ALLOWED_ROLE_IDS or DISCORD_ALLOWED_USER_IDS.');
    process.exit(2);
  }

  client.login(CONFIG.token).catch((error) => {
    console.error(`login failed: ${error.message}`);
    process.exit(1);
  });
}
