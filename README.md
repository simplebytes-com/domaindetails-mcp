# DomainDetails

Domain information lookup tool - CLI, library, and MCP server.

Look up RDAP, WHOIS, and comprehensive domain information using modern protocols with automatic fallback.

## Features

- **CLI Tool**: Quick domain lookups from the command line
- **Library**: Import into your Node.js projects
- **MCP Server**: Integration with Claude Desktop and other MCP clients
- **RDAP First**: Uses modern RDAP protocol for structured domain data
- **WHOIS Fallback**: Automatically falls back to WHOIS when RDAP fails
- **50+ TLDs**: Built-in support for common gTLDs and ccTLDs

## Installation

```bash
npm install domaindetails
```

Or use directly with npx:

```bash
npx domaindetails example.com
```

## Usage

### CLI

```bash
# Basic lookup
npx domaindetails example.com

# Prefer WHOIS over RDAP
npx domaindetails example.com --whois

# Include raw protocol data
npx domaindetails example.com --raw

# Show help
npx domaindetails --help
```

### Library

```javascript
import { lookup, DomainLookup } from 'domaindetails';

// Simple lookup
const result = await lookup('example.com');
console.log(result);

// With options
const client = new DomainLookup();
const result = await client.lookup('google.com', {
  preferWhois: false,
  includeRaw: true
});

// RDAP only
const rdapResult = await client.rdap('example.com');

// WHOIS only
const whoisResult = await client.whois('example.com');
```

### MCP Server

Start the MCP server for use with AI assistants and IDEs:

```bash
npx domaindetails --mcp
```

#### Claude Desktop

Add to your Claude Desktop configuration:

**MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "domaindetails": {
      "command": "npx",
      "args": ["-y", "domaindetails", "--mcp"]
    }
  }
}
```

#### Claude Code

Add to your Claude Code MCP settings:

```bash
claude mcp add domaindetails -- npx -y domaindetails --mcp
```

Or manually add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "domaindetails": {
      "command": "npx",
      "args": ["-y", "domaindetails", "--mcp"]
    }
  }
}
```

#### Cursor

Add to your Cursor MCP configuration at `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "domaindetails": {
      "command": "npx",
      "args": ["-y", "domaindetails", "--mcp"]
    }
  }
}
```

#### Windsurf

Add to your Windsurf MCP configuration at `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "domaindetails": {
      "command": "npx",
      "args": ["-y", "domaindetails", "--mcp"]
    }
  }
}
```

#### Other MCP Clients

For any MCP-compatible client, use:
- **Command**: `npx`
- **Args**: `["-y", "domaindetails", "--mcp"]`

Or use the standalone MCP package:
- **Command**: `npx`
- **Args**: `["-y", "domaindetails-mcp"]`

## API Reference

### `lookup(domain, options)`

Main lookup function with RDAP primary, WHOIS fallback.

```javascript
import { lookup } from 'domaindetails';

const result = await lookup('example.com', {
  preferWhois: false,  // Use WHOIS as primary method
  includeRaw: false    // Include raw protocol response
});
```

### `rdap(domain, options)`

RDAP-only lookup.

```javascript
import { rdap } from 'domaindetails';

const result = await rdap('example.com');
```

### `whois(domain, options)`

WHOIS-only lookup.

```javascript
import { whois } from 'domaindetails';

const result = await whois('example.com');
```

### `DomainLookup` Class

Full-featured client for multiple lookups.

```javascript
import { DomainLookup } from 'domaindetails';

const client = new DomainLookup();

// Multiple lookups with same client
const result1 = await client.lookup('example.com');
const result2 = await client.lookup('google.com');
const result3 = await client.rdap('github.com');
const result4 = await client.whois('twitter.com');
```

### Response Format

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
    "contacts": [...]
  }
}
```

## Supported TLDs

**Generic TLDs**: com, net, org, info, biz, name, pro, xyz, top, site, online, tech, store, app, dev, io, ai, co, me, tv, cc

**Country Code TLDs**: uk, ca, au, de, fr, nl, be, ch, at, it, es, se, no, dk, fi, ie, pl, cz, sk, hu, ro, bg, hr, si, lv, lt, ee

For unsupported TLDs, the library fetches registry information from IANA's bootstrap service.

## MCP Tools

When used as an MCP server, the following tool is available:

### `domain_lookup`

Look up comprehensive domain information.

**Parameters:**
- `domain` (string, required): The domain name to look up
- `prefer_whois` (boolean, optional): Use WHOIS as primary method
- `include_raw` (boolean, optional): Include raw protocol response

## Development

```bash
# Clone repository
git clone https://github.com/simplebytes-com/domaindetails-mcp.git
cd domaindetails-mcp

# Install dependencies
npm install

# Build
npm run build

# Test CLI
node build/cli.js example.com

# Test MCP server
node build/mcp-server.js
```

## License

MIT

## Support

- GitHub Issues: https://github.com/simplebytes-com/domaindetails-mcp/issues
- Website: https://domaindetails.com

## Related Projects

- [DomainDetails.com](https://domaindetails.com) - Full-featured domain research SaaS
- [rdap-mcp](https://github.com/simplebytes-com/rdap-mcp) - Simple RDAP-only MCP server
