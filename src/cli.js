import { DomainLookup } from './lib.js';

const args = process.argv.slice(2);

// Check for help flag
if (args.includes('--help') || args.includes('-h') || args.length === 0) {
  console.log(`
domaindetails - Domain information lookup tool

Usage:
  npx domaindetails <domain> [options]

Options:
  --whois         Use WHOIS instead of RDAP as primary method
  --raw           Include raw protocol response data
  --json          Output as formatted JSON (default)
  --mcp           Start as MCP server (for Claude Desktop, etc.)
  --help, -h      Show this help message

Examples:
  npx domaindetails example.com
  npx domaindetails google.com --whois
  npx domaindetails github.io --raw
  npx domaindetails --mcp

Programmatic Usage:
  import { lookup, DomainLookup } from 'domaindetails';

  // Simple lookup
  const result = await lookup('example.com');

  // With options
  const client = new DomainLookup();
  const result = await client.lookup('example.com', { preferWhois: true });
`);
  process.exit(0);
}

// Check for MCP server mode
if (args.includes('--mcp')) {
  // Start MCP server
  const { startMcpServer } = await import('./mcp-server.js');
  startMcpServer();
} else {
  // CLI mode - lookup domain
  const domain = args.find(arg => !arg.startsWith('--'));

  if (!domain) {
    console.error('Error: Please provide a domain name');
    console.error('Usage: npx domaindetails <domain>');
    process.exit(1);
  }

  const preferWhois = args.includes('--whois');
  const includeRaw = args.includes('--raw');

  const client = new DomainLookup();

  try {
    const result = await client.lookup(domain, { preferWhois, includeRaw });
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(JSON.stringify({
      error: true,
      message: error.message,
      domain
    }, null, 2));
    process.exit(1);
  }
}
