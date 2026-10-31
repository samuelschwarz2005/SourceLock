--[[
    SourceLock — shared configuration and helpers.

    Loaded on BOTH sides via `shared_script 'config.lua'`, so keep this file
    free of natives that only exist on the server or only on the client.
]]

SourceLock = {}

-- Path of the protected client chunk, relative to the resource root.
-- This file must never be declared in fxmanifest.lua.
SourceLock.payloadFile = 'client/payload/client_logic.lua'

-- Handshake tuning (all values in milliseconds unless noted).
SourceLock.challengeTtl      = 10000  -- a ticket is only valid for this long
SourceLock.challengeCooldown = 3000   -- minimum gap between two tickets per player
SourceLock.challengeBudget   = 6      -- max tickets per player per minute
SourceLock.deliveryCooldown  = 10000  -- minimum gap between two full deliveries
SourceLock.chunkSize         = 24000  -- bytes per network chunk
SourceLock.retryDelay        = 5000   -- client re-requests the payload after this
SourceLock.maxAttempts       = 12     -- client stops asking after this many tries
SourceLock.spawnDelay        = 1500   -- settle time after spawn before executing

SourceLock.debug = false

local PREFIX = '^3[SourceLock]^7'

--- Print a prefixed, optionally formatted message to the console.
function SourceLock.log(fmt, ...)
    if select('#', ...) > 0 then
        fmt = string.format(fmt, ...)
    end
    print(('%s %s'):format(PREFIX, tostring(fmt)))
end

--- Same as log(), but only when SourceLock.debug is enabled.
function SourceLock.debugLog(fmt, ...)
    if not SourceLock.debug then return end
    SourceLock.log(fmt, ...)
end

--[[
    FNV-1a (32-bit) returned as 8 uppercase hex characters.

    Both sides hash the exact payload string, so the client can reject
    anything that is not the byte-for-byte file the server read from disk.
    This is an integrity check, not a signature: it catches a truncated or
    tampered delivery, not an attacker who already controls the client.
]]
function SourceLock.hash(value)
    local hash = 0x811C9DC5
    for index = 1, #value do
        hash = hash ~ value:byte(index)
        hash = (hash * 0x01000193) & 0xFFFFFFFF
    end
    return string.format('%08X', hash)
end

--[[
    Environment for the protected chunk.

    The chunk gets a table whose __index falls back to _G (so natives,
    CreateThread, RegisterCommand, ... keep working) while SL is a stable,
    documented surface the payload can rely on.
]]
function SourceLock.createEnv()
    local env = setmetatable({}, { __index = _G })

    env.SL = {
        resource = GetCurrentResourceName(),
        version  = '1.0.0',
        hash     = SourceLock.hash,
        log      = function(fmt, ...)
            if select('#', ...) > 0 then
                fmt = string.format(fmt, ...)
            end
            print(('%s %s'):format(PREFIX, tostring(fmt)))
        end,
    }

    return env
end
