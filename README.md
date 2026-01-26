# HFS Tarpit Plugin

This plugin allows you to intentionally slow down HTTP responses for specific patterns, useful for deterring bots, scanners, and malicious crawlers.

## Features

- **User Agent Matching**: Slow down responses based on User-Agent patterns
- **URL Matching**: Tarpit specific URL patterns (e.g., `*.php`, `/admin/*`)
- **Honeypot**: Answer trash with garbage.
- **Response Code Matching**: Slow down responses with specific HTTP status codes (e.g., 404, 403)
- **Configurable Speed**: Set the exact bytes/second for throttled responses
- **IP Whitelist**: Exclude trusted IPs from tarpitting (supports CIDR notation)
- **Logging**: Optional logging of tarpit activations

## Configuration

### Basic Settings
- **Enable Tarpit**: Master switch to enable/disable functionality
- **Response Speed**: Set bytes per second

### Pattern Matching

All patterns support wildcards:
- `*` matches any characters
- `?` matches single character

**Examples:**
- User Agents: `*bot*`, `curl*`, `*scanner*`, `python-requests/*`
- URLs: `*.php`, `/admin/*`, `*.env`, `/wp-login.php`
- Response Codes: `404`, `403`, `401`

### IP Whitelist

Add trusted IPs that should never be tarpitted:
- Single IP: `192.168.1.100`
- CIDR range: `192.168.1.0/24`, `10.0.0.0/8`

## Use Cases

1. **Bot Deterrence**: Slow down known bot user agents
2. **Scanner Protection**: Tarpit requests for non-existent files (404s)
3. **Admin Protection**: Slow down access attempts to admin URLs
4. **Vulnerability Scanners**: Catch requests for common vulnerability paths

## Performance Notes

- Whitelisted IPs are checked first for performance
- Pattern matching is case-insensitive
- The plugin works in the response phase, so HFS still processes the request normally

--------------------------------

## Key Features:

1. **User Agent Matching**: Match patterns like `*bot*`, `curl*`, `*scanner*`
2. **URL Pattern Matching**: Match URLs like `*.php`, `/admin/*`, `*.env`
3. **Response Code Matching**: Slow down specific HTTP status codes (404, 403, etc.)
4. **Configurable Speed**: Set exact bytes/second throttling
5. **IP Whitelist**: Exclude trusted IPs (supports CIDR)
6. **Wildcard Support**: Use `*` and `?` in patterns
7. **Logging**: Optional logging of tarpit activations
8. **Stream Support**: Handles both string/buffer and stream responses

The plugin uses HFS's middleware system to intercept responses and throttle them byte-by-byte when patterns match. 
This makes it extremely effective at wasting the time of malicious crawlers while having minimal impact on legitimate users (especially with the whitelist feature).
