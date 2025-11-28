# DomainDetails MCP Server

A Model Context Protocol (MCP) server that provides comprehensive domain research tools including RDAP, WHOIS, and DNS lookup capabilities.

## Features

- **RDAP First**: Uses modern RDAP protocol for structured domain data
- **WHOIS Fallback**: Automatically falls back to WHOIS when RDAP fails
- **Registry Detection**: Automatically detects the correct RDAP/WHOIS server for any TLD
- **Comprehensive Coverage**: Supports 50+ TLDs including gTLDs and ccTLDs
- **Easy Integration**: Works with any MCP-compatible client (Claude Desktop, IDEs, etc.)

## Installation

```bash
npm install domaindetails-mcp
```

Or use directly with npx:

```bash
npx domaindetails-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop configuration file:

**MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "domaindetails": {
      "command": "npx",
      "args": ["-y", "domaindetails-mcp"]
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "domaindetails": {
      "command": "domaindetails-mcp"
    }
  }
}
```

## Available Tools

### `domain_lookup`

Look up comprehensive domain information using RDAP protocol with WHOIS fallback.

**Parameters:**
- `domain` (string, required): The domain name to look up (e.g., example.com)
- `prefer_whois` (boolean, optional): If true, use WHOIS instead of RDAP as primary method
- `include_raw` (boolean, optional): If true, include raw protocol response data

**Example Response:**
```json
{
  "domain": "example.com",
  "found": true,
  "method": "rdap",
  "timestamp": "2025-01-21T10:30:00Z",
  "status": ["client transfer prohibited"],
  "nameservers": ["ns1.example.com", "ns2.example.com"],
  "rdap": {
    "registration_date": "1995-08-14T04:00:00Z",
    "expiration_date": "2025-08-13T04:00:00Z",
    "contacts": [...],
    "dnssec": {...}
  }
}
```

## Supported TLDs

The server includes built-in registry detection for 50+ TLDs:

**Generic TLDs**: com, net, org, info, biz, name, pro, xyz, top, site, online, tech, store, app, dev, io, ai, co, me, tv, cc

**Country Code TLDs**: uk, ca, au, de, fr, nl, be, ch, at, it, es, se, no, dk, fi, ie, pl, cz, sk, hu, ro, bg, hr, si, lv, lt, ee

For unsupported TLDs, the server will attempt to fetch registry information from IANA's bootstrap service.

## Related Packages

- **[domaindetails](https://www.npmjs.com/package/domaindetails)** - CLI tool and library for domain lookups (includes this MCP server)

## Development

```bash
# Clone repository
git clone https://github.com/simplebytes-com/domaindetails-mcp.git
cd domaindetails-mcp

# Install dependencies
npm install

# Build
npm run build

# Test locally
node build/index.js
```

## License

MIT

## Support

For issues and questions:
- GitHub Issues: https://github.com/simplebytes-com/domaindetails-mcp/issues
- Website: https://domaindetails.com

## Related Projects

- [DomainDetails.com](https://domaindetails.com) - Full-featured domain research SaaS
- [domaindetails](https://www.npmjs.com/package/domaindetails) - CLI and library version
