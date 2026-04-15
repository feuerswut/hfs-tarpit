exports.description = "Slow down responses for specific user agents, URLs, and response codes to deter bots and malicious crawlers"
exports.version = 4
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
                $width: 8
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

    // Store for honeypot-trapped IPs
    const honeypotIPs = new Map() // { ip: { timer: timeoutId, startTime: timestamp } }

    // Helper function to match wildcards
    function matchesPattern(str, pattern) {
        if (!str || !pattern) return false
        const regexPattern = pattern
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.')
        return new RegExp('^' + regexPattern + '$', 'i').test(str)
    }

    // Helper function to check if IP is whitelisted
    function isWhitelisted(ip, whitelist) {
        if (!whitelist || whitelist.length === 0) return false
        
        for (const entry of whitelist) {
            if (!entry.enabled) continue
            const mask = entry.ip
            if (!mask) continue
            
            try {
                if (misc.ipMatch(ip, mask)) {
                    return true
                }
            } catch (e) {
                api.log('Invalid IP mask:', mask, e.message)
            }
        }
        return false
    }

    // Add IP to honeypot
    function activateHoneypot(ip, duration, logMatches) {
        // Clear existing timer if any
        if (honeypotIPs.has(ip)) {
            clearTimeout(honeypotIPs.get(ip).timer)
        }

        // Set new timer
        const timer = setTimeout(() => {
            honeypotIPs.delete(ip)
            if (logMatches) {
                api.log(`Honeypot deactivated for ${ip} (timeout)`)
            }
        }, duration * 1000)

        honeypotIPs.set(ip, {
            timer: timer,
            startTime: Date.now()
        })

        if (logMatches) {
            api.log(`Honeypot activated for ${ip} (duration: ${duration}s)`)
        }
    }

    // Reset honeypot timer for IP
    function resetHoneypotTimer(ip, duration) {
        if (honeypotIPs.has(ip)) {
            const entry = honeypotIPs.get(ip)
            clearTimeout(entry.timer)
            
            const timer = setTimeout(() => {
                honeypotIPs.delete(ip)
            }, duration * 1000)
            
            entry.timer = timer
            entry.startTime = Date.now()
        }
    }

    // Create infinite "a" stream
    function createHoneypotStream(ctx, speed) {
        const { Readable } = require('stream')
        const stream = new Readable({
            read() {}
        })

        const bytesPerSecond = speed || 0.1
        // Send in 64-byte chunks to reduce the number of active timers ~64x
        const CHUNK_SIZE = 64
        const chunkDelay = (1000 / bytesPerSecond) * CHUNK_SIZE
        const chunk = Buffer.alloc(CHUNK_SIZE, 'a'.charCodeAt(0))

        let stopped = false
        stream.on('close', () => { stopped = true; stream.push(null) })

        const sendChunk = () => {
            if (stopped || ctx.isAborted()) {
                stream.push(null)
                return
            }
            stream.push(chunk)
            setTimeout(sendChunk, chunkDelay)
        }

        sendChunk()
        return stream
    }

    // Middleware to intercept and slow down responses
    exports.middleware = ctx => {
        const config = {
            enabled: api.getConfig('enabled'),
            speed: api.getConfig('speed'),
            honeypotSpeed: api.getConfig('honeypotSpeed'),
            honeypotDuration: api.getConfig('honeypotDuration'),
            userAgentMasks: api.getConfig('userAgentMasks'),
            urlMasks: api.getConfig('urlMasks'),
            responseCodes: api.getConfig('responseCodes'),
            logMatches: api.getConfig('logMatches'),
            whitelistIPs: api.getConfig('whitelistIPs')
        }

        if (!config.enabled) return

        const clientIP = ctx.ip
        
        // Check whitelist first
        if (isWhitelisted(clientIP, config.whitelistIPs)) {
            return
        }

        // Check if IP is in honeypot
        if (honeypotIPs.has(clientIP)) {
            resetHoneypotTimer(clientIP, config.honeypotDuration)
            
            if (config.logMatches) {
                api.log(`Honeypot response sent to ${clientIP} (timer reset)`)
            }

            // Send infinite "a" stream
            ctx.status = 200
            ctx.type = 'text/plain'
            ctx.body = createHoneypotStream(ctx, config.honeypotSpeed)
            return true // Stop further processing
        }

        let shouldTarpit = false
        let shouldActivateHoneypot = false
        let reason = ''

        // Check User Agent
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

        // Check URL pattern
        if (!shouldTarpit && config.urlMasks && config.urlMasks.length > 0) {
            const url = ctx.path
            for (const mask of config.urlMasks) {
                if (!mask.enabled) continue
                if (matchesPattern(url, mask.pattern)) {
                    shouldTarpit = true
                    reason = `URL matches "${mask.pattern}"`
                    
                    // Check if this should activate honeypot
                    if (mask.honeypot) {
                        shouldActivateHoneypot = true
                    }
                    break
                }
            }
        }

        // Activate honeypot if needed
        if (shouldActivateHoneypot) {
            activateHoneypot(clientIP, config.honeypotDuration, config.logMatches)
            
            // Send infinite "a" stream immediately
            ctx.status = 200
            ctx.type = 'text/plain'
            ctx.body = createHoneypotStream(ctx, config.honeypotSpeed)
            return true // Stop further processing
        }

        // Return upstream function to check response code
        return async () => {
            // Check response code (only available in upstream)
            if (!shouldTarpit && config.responseCodes && config.responseCodes.length > 0) {
                const statusCode = ctx.status
                for (const codeEntry of config.responseCodes) {
                    if (!codeEntry.enabled) continue
                    if (statusCode === codeEntry.code) {
                        shouldTarpit = true
                        reason = `Response code is ${statusCode}`
                        break
                    }
                }
            }

            if (!shouldTarpit) return

            if (config.logMatches) {
                api.log(`Tarpit activated for ${clientIP}: ${reason}`)
            }

            // Implement the tarpit
            const body = ctx.body
            if (!body) return

            // Convert body to buffer if it's a string
            let buffer
            if (typeof body === 'string') {
                buffer = Buffer.from(body)
            } else if (Buffer.isBuffer(body)) {
                buffer = body
            } else if (body.pipe) {
                // It's a stream - we'll handle this differently
                const originalStream = body
                const { PassThrough } = require('stream')
                const throttle = new PassThrough()
                
                let bytesWritten = 0
                const bytesPerSecond = config.speed || 100
                const chunkDelay = 1000 / bytesPerSecond // ms per byte
                
                // Send in 64-byte chunks to reduce active timer count
                const CHUNK_SIZE = 64
                const adjustedDelay = chunkDelay * CHUNK_SIZE
                let streamStopped = false
                throttle.on('close', () => { streamStopped = true })

                originalStream.on('data', chunk => {
                    originalStream.pause()
                    let offset = 0

                    const sendChunk = () => {
                        if (streamStopped || ctx.isAborted()) {
                            throttle.end()
                            return
                        }
                        if (offset < chunk.length) {
                            const end = Math.min(offset + CHUNK_SIZE, chunk.length)
                            throttle.write(chunk.slice(offset, end))
                            bytesWritten += (end - offset)
                            offset = end
                            setTimeout(sendChunk, adjustedDelay)
                        } else {
                            originalStream.resume()
                        }
                    }

                    sendChunk()
                })
                
                originalStream.on('end', () => throttle.end())
                originalStream.on('error', err => throttle.destroy(err))
                
                ctx.body = throttle
                return
            } else {
                return // Can't handle this body type
            }

            // For string/buffer bodies, create a slow stream
            const { Readable } = require('stream')
            const slowStream = new Readable({
                read() {}
            })

            const bytesPerSecond = config.speed || 100
            const CHUNK_SIZE = 64
            const chunkDelay = (1000 / bytesPerSecond) * CHUNK_SIZE // ms per chunk
            let offset = 0
            let slowStopped = false
            slowStream.on('close', () => { slowStopped = true })

            const sendChunk = () => {
                if (slowStopped || ctx.isAborted()) {
                    slowStream.push(null)
                    return
                }
                if (offset < buffer.length) {
                    const end = Math.min(offset + CHUNK_SIZE, buffer.length)
                    slowStream.push(buffer.slice(offset, end))
                    offset = end
                    setTimeout(sendChunk, chunkDelay)
                } else {
                    slowStream.push(null) // End the stream
                }
            }

            sendChunk()
            ctx.body = slowStream
        }
    }

    // Cleanup on unload
    exports.unload = () => {
        // Clear all honeypot timers
        for (const [ip, entry] of honeypotIPs.entries()) {
            clearTimeout(entry.timer)
        }
        honeypotIPs.clear()
        api.log('Tarpit plugin unloaded, all honeypot timers cleared')
    }
}
