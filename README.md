# SourceLock
SourceLock is a lightweight FiveM security utility built to stop backdoors and script dumping. It uses an external Node.js scanner to catch obfuscated "cipher" code, hidden webhooks, and rogue requests before boot. At runtime, a dynamic server-to-client Lua loader keeps scripts out of the manifest, protecting code from memory dumpers.
