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
SourceLock.challengeTtl      = 10000   -- a ticket is only valid for this long
SourceLock.challengeCooldown = 3000    -- minimum gap between two tickets per player
SourceLock.challengeBudget   = 6       -- max tickets per player per minute
SourceLock.maxResponses      = 30      -- max challenge responses per player per minute
SourceLock.deliveryCooldown  = 10000   -- minimum gap between two full deliveries
SourceLock.deliveryTimeout   = 30000   -- give up waiting for a delivery ack after this
SourceLock.chunkSize         = 24000   -- bytes per network chunk
SourceLock.maxPayloadBytes   = 5242880 -- refuse to serve a payload larger than this (5 MB)
SourceLock.retryDelay        = 5000    -- client re-requests the payload after this
SourceLock.maxAttempts       = 12      -- client stops asking after this many tries
SourceLock.spawnDelay        = 1500    -- settle time after spawn before executing

-- Every value above is clamped by SourceLock.sanitize() at the bottom of this
-- file. Config is code: chunkSize = 0 would hang the server building chunks and
-- retryDelay = 0 would turn the client retry loop into a request flood.

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
    Two-pass FNV-1a: 16 uppercase hex characters (64 bits).

    Both sides hash the exact payload string, so the client can reject
    anything that is not the byte-for-byte file the server read from disk.
    A single 32-bit pass is cheap to collide with on purpose; hashing forwards
    and backwards doubles the digest for the cost of one extra read.

    This is an integrity check, not a signature: it catches a truncated,
    corrupted or casually tampered delivery, not an attacker who already
    controls the client. Nothing sent to a client can be verified against them.
]]
function SourceLock.hash(value)
    local length = #value
    local forward = 0x811C9DC5
    local backward = 0x811C9DC5

    for index = 1, length do
        forward = ((forward ~ value:byte(index)) * 0x01000193) & 0xFFFFFFFF
        backward = ((backward ~ value:byte(length - index + 1)) * 0x01000193) & 0xFFFFFFFF
    end

    return string.format('%08X%08X', forward, backward)
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

--[[
    Validate the configuration before anything uses it.

    Bounds are safety rails, not preferences: a chunk size of 0 makes
    `math.ceil(#payload / chunkSize)` infinite and the delivery loop never
    ends, a retry delay of 0 turns the client into a request flood, and a
    payloadFile containing '..' would read outside the resource folder.
    Anything out of range is clamped or rejected, and the reason is logged.
]]
function SourceLock.sanitize()
    local function clamp(value, minimum, maximum, fallback)
        value = tonumber(value) or fallback
        if value ~= value then return fallback end -- NaN
        if value < minimum then return minimum end
        if value > maximum then return maximum end
        return math.floor(value)
    end

    SourceLock.challengeTtl      = clamp(SourceLock.challengeTtl, 1000, 60000, 10000)
    SourceLock.challengeCooldown = clamp(SourceLock.challengeCooldown, 500, 60000, 3000)
    SourceLock.challengeBudget   = clamp(SourceLock.challengeBudget, 1, 60, 6)
    SourceLock.maxResponses      = clamp(SourceLock.maxResponses, 1, 600, 30)
    SourceLock.deliveryCooldown  = clamp(SourceLock.deliveryCooldown, 1000, 600000, 10000)
    SourceLock.deliveryTimeout   = clamp(SourceLock.deliveryTimeout, 5000, 300000, 30000)
    SourceLock.chunkSize         = clamp(SourceLock.chunkSize, 1024, 65536, 24000)
    SourceLock.maxPayloadBytes   = clamp(SourceLock.maxPayloadBytes, 1024, 33554432, 5242880)
    SourceLock.retryDelay        = clamp(SourceLock.retryDelay, 1000, 120000, 5000)
    SourceLock.maxAttempts       = clamp(SourceLock.maxAttempts, 1, 50, 12)
    SourceLock.spawnDelay        = clamp(SourceLock.spawnDelay, 0, 30000, 1500)

    local file = SourceLock.payloadFile
    local valid = type(file) == 'string'
        and file ~= ''
        and not file:find('..', 1, true)
        and not file:find('\\', 1, true)
        and file:sub(1, 1) ~= '/'
        and file:lower():sub(-4) == '.lua'

    if not valid then
        SourceLock.log('^1rejected payloadFile %s^7 — falling back to the default path', tostring(file))
        SourceLock.payloadFile = 'client/payload/client_logic.lua'
    end
end

SourceLock.sanitize()
