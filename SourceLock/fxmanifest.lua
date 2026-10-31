fx_version 'cerulean'
game 'gta5'
lua54 'yes'

name 'SourceLock'
author 'SourceLock'
description 'Server-delivered client payload: keeps protected client Lua out of the manifest and client cache.'
version '1.0.0'

shared_script 'config.lua'

server_scripts {
    'server/main.lua',
}

client_scripts {
    'client/init.lua',
}

--[[
    ------------------------------------------------------------------
    DO NOT add the payload here.
    ------------------------------------------------------------------
    `client/payload/` is read on the server with LoadResourceFile() and
    streamed to the client after the handshake in server/main.lua.

    Adding it to client_scripts (or to a `files {}` block) puts it straight
    back into the manifest and the client's resource cache, which is exactly
    what this resource exists to avoid.

    Only an init file that knows how to ask for the payload belongs in
    client_scripts.
]]
