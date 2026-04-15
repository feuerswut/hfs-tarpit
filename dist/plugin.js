exports.description = "Slow down responses for specific user agents, URLs, and response codes to deter bots and malicious crawlers"
exports.version = 5
exports.apiRequired = 12.97
exports.repo = "Feuerswut/hfs-tarpit"


exports.config = {
    enabled: {
        type: 'boolean',
        label: 'Enable Tarpit',
        defaultValue: true,
        helperText: 'Master switch to enable/disable the tarpit'
    },
    speed: {
        type: 'number',
        label: 'Response Speed (bytes/second)',
        defaultValue: 0.5,
        min: 0.001,
        max: 1000,
        helperText: 'How many bytes per second to send when tarpit is triggered',
        showIf: values => values.enabled
    },
    honeypotSpeed: {
        type: 'number',
        label: 'Honeypot Speed (bytes/second)',
        defaultValue: 4,
        min: 0.001,
        max: 1000,
        helperText: 'How many bytes per second to send when honeypot is active',
        showIf: values => values.enabled
    },
    honeypotDuration: {
        type: 'number',
        label: 'Honeypot Duration (seconds)',
        defaultValue: 60,
        min: 15,
        max: 6000,
        helperText: 'How long an IP stays in honeypot mode (resets on each request)',
        showIf: values => values.enabled
    },
    userAgentMasks: {
        type: 'array',
        label: 'User Agent Patterns',
        defaultValue: [],
        helperText: 'Patterns to match against User-Agent header (supports wildcards)',
        showIf: values => values.enabled,
        fields: {
            pattern: {
                type: 'string',
                label: 'Pattern',
                helperText: 'Use * as wildcard (e.g., *bot*, curl*, *scanner*)',
                $width: 4
            },
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 2
            }
        }
    },
    urlMasks: {
        type: 'array',
        label: 'URL Patterns',
        defaultValue: [],
        helperText: 'Patterns to match against requested URLs (supports wildcards)',
        showIf: values => values.enabled,
        fields: {
            pattern: {
                type: 'string',
                label: 'Pattern',
                helperText: 'Use * as wildcard (e.g., *.php, /admin/*, *.env)',
                $width: 4
            },
            honeypot: {
                type: 'boolean',
                label: 'Honeypot',
                defaultValue: false,
                helperText: 'Activate honeypot mode for this pattern',
                $width: 1.4
            },
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 1.2
            }
        }
    },
    responseCodes: {
        type: 'array',
        label: 'Response Code Patterns',
        defaultValue: [],
        helperText: 'Slow down responses with specific HTTP status codes',
        showIf: values => values.enabled,
        fields: {
            code: {
                type: 'number',
                label: 'Status Code',
                helperText: 'HTTP status code (e.g., 404, 403)',
                min: 100,
                max: 599,
                $width: 4
            },
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 2
            }
        }
    },
    logMatches: {
        type: 'boolean',
        label: 'Log Tarpit Activations',
        defaultValue: true,
        helperText: 'Log when tarpit is triggered',
        showIf: values => values.enabled
    },
    whitelistIPs: {
        type: 'array',
        label: 'IP Whitelist',
        defaultValue: [],
        helperText: 'IPs that will never be tarpitted (supports CIDR notation)',
        showIf: values => values.enabled,
        fields: {
            ip: {
                type: 'net_mask',
                label: 'IP/CIDR',
                helperText: 'e.g., 192.168.1.0/24 or 10.0.0.5',
                $width: 4
            },
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 2
            }
        }
    }
}

exports.init = api => {
    const { _, misc } = api
    const { Readable, PassThrough } = require('stream')

    // -------------------------------------------------------------------------
    // Stream pool — hard cap of 20 concurrent tarpit/honeypot streams.
    // Map preserves insertion order so the first entry is always the oldest.
    // Each slot: { kill(), timeoutTimer, startTime, ip }
    // -------------------------------------------------------------------------
    const MAX_STREAMS = 20
    const STREAM_TIMEOUT_MS = 10 * 60 * 1000 // 10 minutes
    const streamPool = new Map()
    let nextStreamId = 0

    // Register a new stream. If the pool is full, kills the oldest first.
    // killFn must synchronously stop the stream loop and destroy/end the stream.
    // Returns the assigned stream id (pass to releaseStream on natural close).
    function registerStream(ip, killFn) {
        if (streamPool.size >= MAX_STREAMS) {
            const [oldestId, oldest] = streamPool.entries().next().value
            api.log(`tarpit: pool full (${MAX_STREAMS}), evicting oldest stream id=${oldestId} ip=${oldest.ip}`)
            oldest.kill()
            releaseStream(oldestId) // force-remove; 'close' will be a no-op
        }

        const id = ++nextStreamId
        const timeoutTimer = setTimeout(() => {
            const entry = streamPool.get(id)
            if (!entry) return
            api.log(`tarpit: stream id=${id} ip=${entry.ip} killed after 10-minute timeout`)
            entry.kill()
            releaseStream(id)
        }, STREAM_TIMEOUT_MS)

        streamPool.set(id, { kill: killFn, timeoutTimer, startTime: Date.now(), ip })
        api.log(`tarpit: stream id=${id} registered for ip=${ip} (pool size=${streamPool.size})`)
        return id
    }

    // Release a slot. Safe to call multiple times for the same id.
    function releaseStream(id) {
        const entry = streamPool.get(id)
        if (!entry) return
        clearTimeout(entry.timeoutTimer)
        streamPool.delete(id)
        api.log(`tarpit: stream id=${id} released (pool size=${streamPool.size})`)
    }

    // -------------------------------------------------------------------------
    // Honeypot IP tracking
    // -------------------------------------------------------------------------
    const honeypotIPs = new Map() // ip -> { timer, startTime }

    function activateHoneypot(ip, duration, logMatches) {
        if (honeypotIPs.has(ip)) {
            clearTimeout(honeypotIPs.get(ip).timer)
        }
        const timer = setTimeout(() => {
            honeypotIPs.delete(ip)
            if (logMatches) api.log(`Honeypot deactivated for ${ip} (timeout)`)
        }, duration * 1000)

        honeypotIPs.set(ip, { timer, startTime: Date.now() })
        if (logMatches) api.log(`Honeypot activated for ${ip} (duration: ${duration}s)`)
    }

    function resetHoneypotTimer(ip, duration) {
        if (!honeypotIPs.has(ip)) return
        const entry = honeypotIPs.get(ip)
        clearTimeout(entry.timer)
        entry.timer = setTimeout(() => { honeypotIPs.delete(ip) }, duration * 1000)
        entry.startTime = Date.now()
    }

    // -------------------------------------------------------------------------
    // Wildcard / whitelist helpers
    // -------------------------------------------------------------------------
    function matchesPattern(str, pattern) {
        if (!str || !pattern) return false
        const regexPattern = pattern
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.')
        return new RegExp('^' + regexPattern + '$', 'i').test(str)
    }

    function isWhitelisted(ip, whitelist) {
        if (!whitelist || whitelist.length === 0) return false
        for (const entry of whitelist) {
            if (!entry.enabled || !entry.ip) continue
            try {
                if (misc.ipMatch(ip, entry.ip)) return true
            } catch (e) {
                api.log('Invalid IP mask:', entry.ip, e.message)
            }
        }
        return false
    }

    // -------------------------------------------------------------------------
    // Stream factories — all go through registerStream / releaseStream
    // -------------------------------------------------------------------------

    // Infinite 'a' stream for honeypot connections
    function createHoneypotStream(ip, speed) {
        const stream = new Readable({ read() {} })
        const CHUNK_SIZE = 64
        const chunkDelay = (1000 / (speed || 0.1)) * CHUNK_SIZE
        const chunk = Buffer.alloc(CHUNK_SIZE, 0x61) // 'a'
        let stopped = false

        const kill = () => {
            stopped = true
            stream.destroy()
        }

        const id = registerStream(ip, kill)

        stream.on('close', () => {
            stopped = true
            releaseStream(id)
        })

        const sendChunk = () => {
            if (stopped) return
            stream.push(chunk)
            setTimeout(sendChunk, chunkDelay)
        }
        sendChunk()

        return stream
    }

    // Throttled stream for a finite string/Buffer body
    function createSlowBufferStream(ip, buffer, speed) {
        const stream = new Readable({ read() {} })
        const CHUNK_SIZE = 64
        const chunkDelay = (1000 / (speed || 100)) * CHUNK_SIZE
        let offset = 0
        let stopped = false

        const kill = () => {
            stopped = true
            stream.destroy()
        }

        const id = registerStream(ip, kill)

        stream.on('close', () => {
            stopped = true
            releaseStream(id)
        })

        const sendChunk = () => {
            if (stopped) {
                stream.push(null)
                return
            }
            if (offset >= buffer.length) {
                stream.push(null)
                return
            }
            const end = Math.min(offset + CHUNK_SIZE, buffer.length)
            stream.push(buffer.slice(offset, end))
            offset = end
            setTimeout(sendChunk, chunkDelay)
        }
        sendChunk()

        return stream
    }

    // Throttled PassThrough wrapper for a streaming body
    function createSlowPassThrough(ip, originalStream, speed) {
        const throttle = new PassThrough()
        const CHUNK_SIZE = 64
        const chunkDelay = (1000 / (speed || 100)) * CHUNK_SIZE
        let stopped = false

        const kill = () => {
            stopped = true
            throttle.destroy()
        }

        const id = registerStream(ip, kill)

        throttle.on('close', () => {
            stopped = true
            releaseStream(id)
        })

        originalStream.on('data', chunk => {
            originalStream.pause()
            let offset = 0

            const sendChunk = () => {
                if (stopped) {
                    throttle.destroy()
                    return
                }
                if (offset >= chunk.length) {
                    originalStream.resume()
                    return
                }
                const end = Math.min(offset + CHUNK_SIZE, chunk.length)
                throttle.write(chunk.slice(offset, end))
                offset = end
                setTimeout(sendChunk, chunkDelay)
            }
            sendChunk()
        })

        originalStream.on('end', () => { if (!stopped) throttle.end() })
        originalStream.on('error', err => throttle.destroy(err))

        return throttle
    }

    // -------------------------------------------------------------------------
    // Middleware
    // -------------------------------------------------------------------------
    exports.middleware = ctx => {
        const config = {
            enabled:         api.getConfig('enabled'),
            speed:           api.getConfig('speed'),
            honeypotSpeed:   api.getConfig('honeypotSpeed'),
            honeypotDuration:api.getConfig('honeypotDuration'),
            userAgentMasks:  api.getConfig('userAgentMasks'),
            urlMasks:        api.getConfig('urlMasks'),
            responseCodes:   api.getConfig('responseCodes'),
            logMatches:      api.getConfig('logMatches'),
            whitelistIPs:    api.getConfig('whitelistIPs')
        }

        if (!config.enabled) return

        const clientIP = ctx.ip

        if (isWhitelisted(clientIP, config.whitelistIPs)) return

        // ---- Honeypot: IP already trapped ----
        if (honeypotIPs.has(clientIP)) {
            resetHoneypotTimer(clientIP, config.honeypotDuration)
            if (config.logMatches) api.log(`Honeypot response sent to ${clientIP} (timer reset)`)

            ctx.status = 200
            ctx.type = 'text/plain'
            ctx.body = createHoneypotStream(clientIP, config.honeypotSpeed)
            return true
        }

        let shouldTarpit = false
        let shouldActivateHoneypot = false
        let reason = ''

        // ---- User-Agent check ----
        const userAgent = ctx.get('user-agent') || ''
        if (config.userAgentMasks && config.userAgentMasks.length > 0) {
            for (const mask of config.userAgentMasks) {
                if (!mask.enabled) continue
                if (matchesPattern(userAgent, mask.pattern)) {
                    shouldTarpit = true
                    reason = `User-Agent matches "${mask.pattern}"`
                    break
                }
            }
        }

        // ---- URL check ----
        if (!shouldTarpit && config.urlMasks && config.urlMasks.length > 0) {
            for (const mask of config.urlMasks) {
                if (!mask.enabled) continue
                if (matchesPattern(ctx.path, mask.pattern)) {
                    shouldTarpit = true
                    reason = `URL matches "${mask.pattern}"`
                    if (mask.honeypot) shouldActivateHoneypot = true
                    break
                }
            }
        }

        // ---- Honeypot activation ----
        if (shouldActivateHoneypot) {
            activateHoneypot(clientIP, config.honeypotDuration, config.logMatches)
            ctx.status = 200
            ctx.type = 'text/plain'
            ctx.body = createHoneypotStream(clientIP, config.honeypotSpeed)
            return true
        }

        // ---- Upstream: response-code check + body throttle ----
        return async () => {
            if (!shouldTarpit && config.responseCodes && config.responseCodes.length > 0) {
                for (const codeEntry of config.responseCodes) {
                    if (!codeEntry.enabled) continue
                    if (ctx.status === codeEntry.code) {
                        shouldTarpit = true
                        reason = `Response code is ${ctx.status}`
                        break
                    }
                }
            }

            if (!shouldTarpit) return

            if (config.logMatches) api.log(`Tarpit activated for ${clientIP}: ${reason}`)

            const body = ctx.body
            if (!body) return

            if (typeof body === 'string' || Buffer.isBuffer(body)) {
                const buf = Buffer.isBuffer(body) ? body : Buffer.from(body)
                ctx.body = createSlowBufferStream(clientIP, buf, config.speed)
            } else if (body.pipe) {
                ctx.body = createSlowPassThrough(clientIP, body, config.speed)
            }
            // all other body types pass through unchanged
        }
    }

    // -------------------------------------------------------------------------
    // Cleanup on unload
    // -------------------------------------------------------------------------
    exports.unload = () => {
        // Kill every active stream
        for (const [id, entry] of streamPool.entries()) {
            entry.kill()
            clearTimeout(entry.timeoutTimer)
        }
        streamPool.clear()

        // Clear all honeypot timers
        for (const [, entry] of honeypotIPs.entries()) {
            clearTimeout(entry.timer)
        }
        honeypotIPs.clear()

        api.log('Tarpit plugin unloaded, all streams and honeypot timers cleared')
    }
}
