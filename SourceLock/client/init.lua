--[[
    SourceLock — client bootstrap.

    This is the ONLY client file in the manifest. It asks the server for the
    protected chunk, verifies its integrity, assembles it and runs it from
    memory. Nothing here is secret: a client-side executor can read this file.
    That is why the server — not this script — decides whether to deliver.
]]

local state = {
    started  = false,
    loaded   = false,
    executed = false,
    attempts = 0,
}

-- Bounds on whatever arrives on the chunk event: a rogue event source (or any
-- other local resource calling TriggerEvent) must not be able to grow this.
local MAX_CHUNK = math.max(1024, (SourceLock.chunkSize or 24000) * 2)
local MAX_BUFFER = SourceLock.maxPayloadBytes or (5 * 1024 * 1024)

local buffer = {
    total    = nil,
    received = 0,
    bytes    = 0,
    parts    = {},
}

local env = SourceLock.createEnv()
local SL = env.SL

local function resetBuffer()
    buffer = { total = nil, received = 0, bytes = 0, parts = {} }
end

--- Verify, compile and execute the assembled payload exactly once.
local function execute(code, expectedHash)
    if state.loaded or state.executed then return end

    local actual = SourceLock.hash(code)
    if actual ~= expectedHash then
        SL.log('^1integrity check failed (expected %s, got %s) — discarded', tostring(expectedHash), actual)
        return
    end

    -- From here the payload is handed to load() exactly once. Retrying after a
    -- compile or runtime error would re-register its commands, threads and
    -- events on an already half-initialised client.
    state.executed = true

    -- 't' = text chunk only; bytecode would sidestep the hash's meaning.
    local chunk, loadError = load(code, '@SourceLock/protected', 't', env)
    if not chunk then
        SL.log('^1compile error: %s', tostring(loadError))
        return
    end

    local ok, runtimeError = pcall(chunk)
    if not ok then
        SL.log('^1runtime error: %s', tostring(runtimeError))
        return
    end

    state.loaded = true
    SL.log('payload loaded (%d bytes, hash %s)', #code, actual)
end

--=====================================================================
-- Handshake
--=====================================================================

RegisterNetEvent('sourcelock:challenge', function(token)
    if state.loaded or state.executed then return end
    if type(token) ~= 'string' or #token == 0 then return end

    TriggerServerEvent('sourcelock:challengeResponse', token)
end)

RegisterNetEvent('sourcelock:chunk', function(chunk)
    if state.loaded or state.executed then return end
    if type(chunk) ~= 'table' then return end

    local index, total, data = chunk.index, chunk.total, chunk.data
    if type(index) ~= 'number' or type(total) ~= 'number' or type(data) ~= 'string' then
        return
    end
    if index < 1 or total < 1 or index > total then return end
    if #data > MAX_CHUNK then return end

    -- A new delivery always starts at 1; drop whatever the old one left behind.
    if index == 1 then resetBuffer() end
    if buffer.total and buffer.total ~= total then resetBuffer() end

    buffer.total = total

    if buffer.parts[index] == nil then
        buffer.parts[index] = data
        buffer.received = buffer.received + 1
        buffer.bytes = buffer.bytes + #data

        if buffer.bytes > MAX_BUFFER then
            SL.log('^1delivery exceeded %d bytes — discarded', MAX_BUFFER)
            resetBuffer()
        end
    end
end)

RegisterNetEvent('sourcelock:complete', function(meta)
    if state.loaded or state.executed then return end
    if type(meta) ~= 'table' or type(meta.total) ~= 'number' or type(meta.hash) ~= 'string' then
        return
    end

    -- A chunk count that could never fit inside the size cap is a lie.
    if meta.total < 1 or meta.total > math.floor(MAX_BUFFER / 1024) then
        SL.log('^1refusing implausible delivery size (%s chunks)', tostring(meta.total))
        return
    end

    if buffer.received ~= meta.total or #buffer.parts ~= meta.total then
        SL.log('incomplete delivery (%d/%d chunks) — will retry', buffer.received, tostring(meta.total))
        resetBuffer()
        TriggerServerEvent('sourcelock:ack')
        return
    end

    local pieces = {}
    for index = 1, meta.total do
        pieces[index] = buffer.parts[index]
    end

    local code = table.concat(pieces)
    resetBuffer()
    execute(code, meta.hash)

    -- Releases the server's in-flight lock so a retry can be delivered.
    TriggerServerEvent('sourcelock:ack')
end)

--=====================================================================
-- Trigger
--=====================================================================

local function startLoading()
    if state.started or state.loaded or state.executed then return end
    state.started = true

    CreateThread(function()
        -- Let the spawn settle: a payload that touches peds, vehicles or the
        -- camera should never run while the player is still on the loading screen.
        Wait(SourceLock.spawnDelay)

        while not state.loaded and not state.executed and state.attempts < SourceLock.maxAttempts do
            state.attempts = state.attempts + 1
            SourceLock.debugLog('requesting payload (attempt %d/%d)', state.attempts, SourceLock.maxAttempts)

            resetBuffer()
            TriggerServerEvent('sourcelock:clientReady')
            Wait(SourceLock.retryDelay)
        end

        if not state.loaded and not state.executed then
            SL.log('^1no payload received — the server refused the handshake or the file is missing')
        end
    end)
end

-- Normal path: the player finishes spawning.
AddEventHandler('playerSpawned', startLoading)

-- Recovery path: the resource was (re)started while the player was already in game.
CreateThread(function()
    while not NetworkIsSessionStarted() do
        Wait(500)
    end

    Wait(SourceLock.spawnDelay)
    startLoading()
end)
