exports.description = "Slow down responses for specific user agents, URLs, and response codes to deter bots and malicious crawlers"
exports.version = 2
exports.apiRequired = 12.97
exports.repo = "feuerswut/hfs-tarpit"

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
        defaultValue: 100,
        min: 1,
        max: 100000,
        helperText: 'How many bytes per second to send when tarpit is triggered',
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
            enabled: {
                type: 'boolean',
                label: 'Enabled',
                defaultValue: true,
                $width: 2
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

    // Middleware to intercept and slow down responses
    exports.middleware = ctx => {
        const config = {
            enabled: api.getConfig('enabled'),
            speed: api.getConfig('speed'),
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

        let shouldTarpit = false
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
                    break
                }
            }
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
                
                originalStream.on('data', chunk => {
                    originalStream.pause()
                    let offset = 0
                    
                    const sendByte = () => {
                        if (offset < chunk.length && !ctx.isAborted()) {
                            throttle.write(Buffer.from([chunk[offset]]))
                            offset++
                            bytesWritten++
                            setTimeout(sendByte, chunkDelay)
                        } else {
                            originalStream.resume()
                        }
                    }
                    
                    sendByte()
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
            const chunkDelay = 1000 / bytesPerSecond // milliseconds per byte
            let offset = 0

            const sendByte = () => {
                if (offset < buffer.length && !ctx.isAborted()) {
                    slowStream.push(Buffer.from([buffer[offset]]))
                    offset++
                    setTimeout(sendByte, chunkDelay)
                } else {
                    slowStream.push(null) // End the stream
                }
            }

            sendByte()
            ctx.body = slowStream
        }
    }
}
