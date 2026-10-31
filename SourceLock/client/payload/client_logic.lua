--[[
    SourceLock — protected payload (example).

    This file is deliberately NOT declared in fxmanifest.lua. It never reaches
    the client cache as a script: the server reads it with LoadResourceFile(),
    streams it after the handshake, and client/init.lua runs it from memory.

    Available in this chunk:
        SL.log(fmt, ...)   console logging with the SourceLock prefix
        SL.version         loader version string
        SL.resource        resource name
        SL.hash(string)    the shared FNV-1a used for integrity checks

    Globals (_G) are reachable through the environment's __index fallback, so
    natives, CreateThread, RegisterCommand, exports, ... all work normally.
    Assignments without `local` land in the chunk environment, not in _G —
    keep that in mind if another resource reads your globals.
]]

local SL = SL

SL.log('protected chunk executing in memory (v%s)', SL.version)

local loadedAt = GetGameTimer()

-- A tiny, harmless command so you can see the payload is alive.
RegisterCommand('slstatus', function()
    SL.log('payload alive since %d ms (resource %s)', loadedAt, SL.resource)
end, false)

CreateThread(function()
    Wait(2000)
    SL.log('ready — type /slstatus to verify the protected chunk is running')
end)
