--[[
    SourceLock — server side.

    Responsibilities
      1. Read the protected chunk from disk once and cache it in memory.
      2. Hand out short-lived, single-use challenge tickets, rate limited per player.
      3. Verify the echoed ticket, then stream the payload to that player only.

    Nothing here trusts the client: the ticket is bound to the requesting
    server id, expires quickly, is invalidated on first use and every attempt
    costs rate-limit budget. One player can never fetch another player's payload.
]]

local RESOURCE = GetCurrentResourceName()
local CHUNK = SourceLock.chunkSize

local payload      -- raw text of SourceLock.payloadFile
local payloadHash  -- SourceLock.hash(payload)

local challenges   = {}   -- [src] = { token = string, expires = number }
local budget       = {}   -- [src] = { count = number, resetAt = number } (tickets)
local responses    = {}   -- [src] = { count = number, resetAt = number } (responses, valid or not)
local lastTicket   = {}   -- [src] = GetGameTimer() of the last issued ticket
local lastDelivery = {}   -- [src] = GetGameTimer() of the last payload delivery
local inFlight     = {}   -- [src] = GetGameTimer() of an un-acknowledged delivery

local function now()
    return GetGameTimer()
end

--[[
    FiveM exposes no CSPRNG, so mix several clocks with a fresh table address.
    Unpredictability is a bonus here rather than the defence: the ticket only
    travels on the player's own connection and is single-use, so it only has
    to defeat other players and blind event spam.
]]
local function newToken()
    local seed = ('%d|%d|%d|%.0f|%s'):format(
        now(),
        os.time(),
        math.random(0, 0x7FFFFFFF),
        os.clock() * 1e6,
        tostring({})
    )
    return SourceLock.hash(seed) .. SourceLock.hash(seed:reverse())
end

--- Read and hash the payload file. Safe to call again after a resource restart.
local function readPayload()
    local code = LoadResourceFile(RESOURCE, SourceLock.payloadFile)

    if type(code) ~= 'string' or #code == 0 then
        payload, payloadHash = nil, nil
        SourceLock.log('^1payload missing or empty: %s^7 — clients stay locked', SourceLock.payloadFile)
        return false
    end

    if #code > SourceLock.maxPayloadBytes then
        payload, payloadHash = nil, nil
        SourceLock.log(
            '^1payload is %d bytes, over the %d byte limit — refusing to cache it',
            #code,
            SourceLock.maxPayloadBytes
        )
        return false
    end

    payload, payloadHash = code, SourceLock.hash(code)
    SourceLock.log('payload cached: %s (%d bytes, hash %s)', SourceLock.payloadFile, #code, payloadHash)
    return true
end

local function isConnected(src)
    return type(src) == 'number' and src > 0 and GetPlayerName(src) ~= nil
end

--- Sliding one-minute budget, so a spamming client is throttled, not served.
local function consumeBudget(src)
    local current = now()
    local entry = budget[src]

    if not entry or current >= entry.resetAt then
        budget[src] = { count = 1, resetAt = current + 60000 }
        return true
    end

    if entry.count >= SourceLock.challengeBudget then
        return false
    end

    entry.count = entry.count + 1
    return true
end

--- Responses get their own budget: a client that only ever sends garbage is
--- still cheap to handle, but it should not be free to keep the handler busy.
local function responseAllowed(src)
    local current = now()
    local entry = responses[src]

    if not entry or current >= entry.resetAt then
        responses[src] = { count = 1, resetAt = current + 60000 }
        return true
    end

    entry.count = entry.count + 1
    return entry.count <= SourceLock.maxResponses
end

local function issueChallenge(src)
    local current = now()

    if lastTicket[src] and (current - lastTicket[src]) < SourceLock.challengeCooldown then
        SourceLock.debugLog('challenge for %d ignored: cooldown', src)
        return
    end

    if not consumeBudget(src) then
        SourceLock.debugLog('challenge for %d ignored: budget exhausted', src)
        return
    end

    lastTicket[src] = current
    local ticket = { token = newToken(), expires = current + SourceLock.challengeTtl }
    challenges[src] = ticket

    TriggerClientEvent('sourcelock:challenge', src, ticket.token)
    SourceLock.debugLog('challenge issued to %d', src)
end

--- Stream the payload in chunks; events have practical size limits.
local function deliver(src)
    local total = math.max(1, math.ceil(#payload / CHUNK))

    for index = 1, total do
        TriggerClientEvent('sourcelock:chunk', src, {
            index = index,
            total = total,
            data  = payload:sub((index - 1) * CHUNK + 1, index * CHUNK),
        })
    end

    TriggerClientEvent('sourcelock:complete', src, {
        total = total,
        hash  = payloadHash,
    })

    SourceLock.log('payload delivered to %d (%d bytes in %d chunk(s))', src, #payload, total)
end

--=====================================================================
-- Handshake
--=====================================================================

-- Client says "I have spawned, may I have the payload?"
RegisterNetEvent('sourcelock:clientReady', function()
    local src = source
    if not isConnected(src) then return end

    issueChallenge(src)
end)

-- Client echoes the ticket it just received.
RegisterNetEvent('sourcelock:challengeResponse', function(token)
    local src = source
    if not isConnected(src) then return end

    if not responseAllowed(src) then
        SourceLock.debugLog('response flood from %d — ignored', src)
        return
    end

    local ticket = challenges[src]
    challenges[src] = nil -- single use, whether it matches or not

    if not ticket then
        SourceLock.debugLog('response from %d without an open challenge', src)
        return
    end

    if type(token) ~= 'string' or #token == 0 or #token > 64 then
        return
    end

    if token ~= ticket.token then
        SourceLock.debugLog('bad token from %d', src)
        return
    end

    if now() > ticket.expires then
        SourceLock.debugLog('expired token from %d', src)
        return
    end

    if not payload then
        SourceLock.log('^1cannot deliver to %d: no payload cached', src)
        return
    end

    local current = now()

    -- A second delivery while the first is still arriving would interleave
    -- chunks and corrupt the client's assembly buffer, so wait for the ack
    -- (or the safety timeout) before starting another one.
    if inFlight[src] and (current - inFlight[src]) < SourceLock.deliveryTimeout then
        SourceLock.debugLog('delivery to %d ignored: previous delivery still in flight', src)
        return
    end

    if lastDelivery[src] and (current - lastDelivery[src]) < SourceLock.deliveryCooldown then
        SourceLock.debugLog('delivery to %d ignored: cooldown', src)
        return
    end

    lastDelivery[src] = current
    inFlight[src] = current
    deliver(src)
end)

-- The client confirms it finished assembling the payload (accepted or
-- rejected), which releases the in-flight lock above.
RegisterNetEvent('sourcelock:ack', function()
    local src = source
    if not isConnected(src) then return end

    inFlight[src] = nil
end)

--=====================================================================
-- Lifecycle
--=====================================================================

AddEventHandler('playerDropped', function()
    local src = source
    challenges[src] = nil
    budget[src] = nil
    responses[src] = nil
    lastTicket[src] = nil
    lastDelivery[src] = nil
    inFlight[src] = nil
end)

AddEventHandler('onResourceStart', function(resource)
    if resource == RESOURCE and not payload then
        readPayload()
    end
end)

-- Reading at load time means the payload is ready before the first player
-- connects; the handler above only covers a restart with lost state.
readPayload()
