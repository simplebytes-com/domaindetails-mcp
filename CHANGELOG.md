# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-30

### Added
- Initial release of domaindetails-mcp
- RDAP protocol support for domain lookups
- WHOIS fallback when RDAP fails
- Automatic registry detection for 50+ TLDs
- Comprehensive domain information including:
  - Registration and expiration dates
  - Domain status codes
  - Nameservers
  - Contact information (registrar, admin, technical)
  - DNSSEC information
- Model Context Protocol (MCP) integration via stdio transport
- `domain_lookup` tool with options for WHOIS preference and raw data
- Built-in support for gTLDs and ccTLDs
- Fallback to IANA bootstrap service for unknown TLDs
- GitHub Actions workflow for automated publishing
- Comprehensive documentation and usage examples

[1.0.0]: https://github.com/simplebytes-com/domaindetails-mcp/releases/tag/v1.0.0
