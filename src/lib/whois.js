import { RegistryDetector } from '../services/registry-detector.js';

export class WhoisClient {
  constructor() {
    this.registryDetector = new RegistryDetector();
    this.timeout = 15000; // 15 seconds timeout for WHOIS
  }

  async lookupDomain(domain) {
    if (!domain || typeof domain !== 'string') {
      throw new Error('Invalid domain provided');
    }

    const cleanDomain = domain.toLowerCase().trim();
    
    // Validate domain format
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(cleanDomain)) {
      throw new Error('Invalid domain format');
    }

    try {
      const whoisServer = await this.registryDetector.getWhoisServer(cleanDomain);
      const result = await this.queryWhoisServer(whoisServer, cleanDomain);
      
      // If result is already structured (from DomainDetails API), return it
      if (result && typeof result === 'object' && result.parsedData) {
        return this.formatApiResponse(result, cleanDomain);
      }
      
      // Otherwise parse as raw WHOIS text (fallback)
      return this.parseWhoisResponse(result, cleanDomain);
      
    } catch (error) {
      throw new Error(`WHOIS lookup failed: ${error.message}`);
    }
  }

  async queryWhoisServer(server, domain) {
    // Use DomainDetails.com backend API for WHOIS lookups
    // This backend has proper WHOIS client implementation
    const domainDetailsApiUrls = [
      `https://api.domaindetails.com/api/whois?domain=${domain}`,
      `http://localhost:3001/api/whois?domain=${domain}` // Fallback for local development
    ];

    for (const apiUrl of domainDetailsApiUrls) {
      try {
        const response = await fetch(apiUrl, {
          method: 'GET',
          headers: {
            'User-Agent': 'RDAP-MCP-Server/1.0.0',
            'Accept': 'application/json'
          },
          signal: AbortSignal.timeout(this.timeout)
        });

        if (response.ok) {
          const data = await response.json();
          
          // Return the full structured response from DomainDetails API
          if (data.parsedData || data.rawData) {
            return data;  // Return the entire structured response
          }
        }
      } catch (error) {
        console.warn(`Failed to query DomainDetails API at ${apiUrl}: ${error.message}`);
        continue;
      }
    }

    // If DomainDetails API fails, return a descriptive message
    return `% WHOIS information not available via DomainDetails API for ${domain}
% Domain: ${domain}
% Attempted servers: ${domainDetailsApiUrls.join(', ')}
% Status: API lookup failed`;
  }

  formatApiResponse(apiResponse, domain) {
    const { parsedData, rawData } = apiResponse;
    
    const result = {
      domain,
      found: true,
      source: 'whois',
      rawData: rawData || null,
      registrar: parsedData?.registrar || null,
      registrant: parsedData?.registrant || null,
      adminContact: null,
      techContact: null,
      billingContact: null,
      nameservers: parsedData?.nameservers || [],
      status: Array.isArray(parsedData?.status) ? parsedData.status : [],
      dates: {},
      dnssec: parsedData?.dnssec || null,
      whoisServer: parsedData?.whoisServer || null
    };

    // Format dates properly
    if (parsedData?.creationDate) {
      result.dates.created = parsedData.creationDate;
    }
    if (parsedData?.expirationDate) {
      result.dates.expires = parsedData.expirationDate;
    }
    if (parsedData?.lastModified) {
      result.dates.updated = parsedData.lastModified;
    }

    // Extract additional information from raw data
    if (rawData) {
      this.enrichFromRawData(result, rawData);
    }

    return result;
  }

  enrichFromRawData(result, rawData) {
    // Extract dates from raw data
    const datePatterns = {
      created: [
        /Registered on:\s*(.+)/i,
        /Creation date:\s*(.+)/i,
        /Created:\s*(.+)/i,
        /Registration date:\s*(.+)/i
      ],
      expires: [
        /Expiry date:\s*(.+)/i,
        /Expires:\s*(.+)/i,
        /Expiration date:\s*(.+)/i,
        /Registry Expiry Date:\s*(.+)/i
      ],
      updated: [
        /Last updated:\s*(.+)/i,
        /Last modified:\s*(.+)/i,
        /Updated date:\s*(.+)/i,
        /Last Changed:\s*(.+)/i
      ]
    };

    for (const [type, patterns] of Object.entries(datePatterns)) {
      if (!result.dates[type]) {
        for (const pattern of patterns) {
          const match = rawData.match(pattern);
          if (match) {
            result.dates[type] = match[1].trim();
            break;
          }
        }
      }
    }

    // Extract nameservers from raw data
    if (!result.nameservers || result.nameservers.length === 0) {
      const nameserverPatterns = [
        /Name servers?:\s*([\s\S]*?)(?:\n\s*\n|\n\s*WHOIS|$)/i,
        /DNS:\s*([\s\S]*?)(?:\n\s*\n|\n\s*WHOIS|$)/i
      ];

      for (const pattern of nameserverPatterns) {
        const match = rawData.match(pattern);
        if (match) {
          const nsLines = match[1].split('\n');
          const nameservers = nsLines
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('-') && !line.startsWith('This'))
            .map(line => line.split(/\s+/)[0])
            .filter(ns => ns && ns.includes('.') && ns.length > 3)
            .slice(0, 10);
          
          if (nameservers.length > 0) {
            result.nameservers = nameservers;
            break;
          }
        }
      }
    }

    // Extract registration status
    const statusPatterns = [
      /Registration status:\s*(.+)/i,
      /Status:\s*(.+)/i,
      /Domain status:\s*(.+)/i
    ];

    for (const pattern of statusPatterns) {
      const match = rawData.match(pattern);
      if (match) {
        const statusText = match[1].trim();
        if (!result.status.includes(statusText)) {
          result.status.push(statusText);
        }
        break;
      }
    }

    // Extract registrar from raw data if not already set
    if (!result.registrar) {
      const registrarPatterns = [
        /Registrar:\s*(.+?)(?:\[|URL:|$)/i,
        /Sponsoring Registrar:\s*(.+)/i
      ];

      for (const pattern of registrarPatterns) {
        const match = rawData.match(pattern);
        if (match) {
          result.registrar = match[1].trim();
          break;
        }
      }
    }

    // Extract registrant information from raw data
    const registrantPatterns = [
      /Registrant:\s*(.+)/i,
      /Registrant Organization:\s*(.+)/i,
      /Registrant Name:\s*(.+)/i
    ];

    for (const pattern of registrantPatterns) {
      const match = rawData.match(pattern);
      if (match) {
        if (!result.registrant) result.registrant = {};
        if (!result.registrant.name && !result.registrant.organization) {
          const value = match[1].trim();
          if (pattern.source.includes('Organization')) {
            result.registrant.organization = value;
          } else {
            result.registrant.name = value;
          }
        }
        break;
      }
    }

    // Extract WHOIS server if not already set
    if (!result.whoisServer) {
      const whoisServerMatch = rawData.match(/Whois Server:\s*(.+)/i);
      if (whoisServerMatch) {
        result.whoisServer = whoisServerMatch[1].trim();
      }
    }

    // Add any additional metadata found
    result.additionalInfo = {};

    // Extract URL if present
    const urlMatch = rawData.match(/URL:\s*(https?:\/\/[^\s\r\n]+)/i);
    if (urlMatch) {
      result.additionalInfo.registrarUrl = urlMatch[1];
    }

    // Extract data validation info
    const validationMatch = rawData.match(/Data validation:\s*([\s\S]*?)(?:\n\s*\n|\n\s*[A-Z])/i);
    if (validationMatch) {
      result.additionalInfo.dataValidation = validationMatch[1].trim();
    }

    // Clean up empty additionalInfo
    if (Object.keys(result.additionalInfo).length === 0) {
      delete result.additionalInfo;
    }
  }

  reconstructWhoisFromParsed(parsedData, domain) {
    if (!parsedData || typeof parsedData !== 'object') {
      return `% No parsed WHOIS data available for ${domain}`;
    }

    let reconstructed = `% WHOIS data reconstructed from DomainDetails API\n`;
    reconstructed += `% Domain: ${domain}\n\n`;

    // Convert parsed data object to WHOIS-like format
    for (const [key, value] of Object.entries(parsedData)) {
      if (value && value !== '') {
        reconstructed += `${key}: ${value}\n`;
      }
    }

    return reconstructed;
  }

  extractWhoisFromHtml(html) {
    // Look for common patterns in HTML that contain WHOIS data
    const patterns = [
      /<pre[^>]*>([\s\S]*?)<\/pre>/i,
      /<code[^>]*>([\s\S]*?)<\/code>/i,
      /class="whois[^"]*"[^>]*>([\s\S]*?)</i
    ];

    for (const pattern of patterns) {
      const match = html.match(pattern);
      if (match && match[1]) {
        // Clean up HTML entities and extra whitespace
        return match[1]
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .replace(/&amp;/g, '&')
          .replace(/&quot;/g, '"')
          .replace(/&#x27;/g, "'")
          .replace(/&#x2F;/g, '/')
          .trim();
      }
    }

    return null;
  }

  parseWhoisResponse(whoisText, domain) {
    if (!whoisText) {
      return {
        domain,
        found: false,
        source: 'whois',
        error: 'No WHOIS data available'
      };
    }

    const result = {
      domain,
      found: true,
      source: 'whois',
      rawData: whoisText,
      registrar: null,
      registrant: null,
      adminContact: null,
      techContact: null,
      billingContact: null,
      nameservers: [],
      status: [],
      dates: {},
      dnssec: null
    };

    const lines = whoisText.split('\n');
    let currentSection = null;

    for (let line of lines) {
      line = line.trim();
      
      if (!line || line.startsWith('%') || line.startsWith('>>')) {
        continue;
      }

      // Parse key-value pairs
      const colonIndex = line.indexOf(':');
      if (colonIndex === -1) continue;

      const key = line.substring(0, colonIndex).trim().toLowerCase();
      const value = line.substring(colonIndex + 1).trim();

      if (!value) continue;

      // Parse common fields
      switch (key) {
        case 'registrar':
        case 'sponsoring registrar':
          result.registrar = value;
          break;

        case 'registrant':
        case 'registrant organization':
        case 'registrant org':
          if (!result.registrant) result.registrant = {};
          result.registrant.organization = value;
          break;

        case 'registrant name':
          if (!result.registrant) result.registrant = {};
          result.registrant.name = value;
          break;

        case 'registrant email':
          if (!result.registrant) result.registrant = {};
          result.registrant.email = value;
          break;

        case 'admin email':
        case 'administrative contact email':
          if (!result.adminContact) result.adminContact = {};
          result.adminContact.email = value;
          break;

        case 'tech email':
        case 'technical contact email':
          if (!result.techContact) result.techContact = {};
          result.techContact.email = value;
          break;

        case 'name server':
        case 'nameserver':
        case 'nserver':
          if (value && !result.nameservers.includes(value.toLowerCase())) {
            result.nameservers.push(value.toLowerCase());
          }
          break;

        case 'domain status':
        case 'status':
          result.status.push(value);
          break;

        case 'creation date':
        case 'created':
        case 'registered':
          result.dates.created = this.parseDate(value);
          break;

        case 'expiry date':
        case 'expires':
        case 'expiration date':
          result.dates.expires = this.parseDate(value);
          break;

        case 'updated date':
        case 'last modified':
        case 'changed':
          result.dates.updated = this.parseDate(value);
          break;

        case 'dnssec':
          result.dnssec = value.toLowerCase();
          break;
      }
    }

    // Clean up empty objects
    if (result.registrant && Object.keys(result.registrant).length === 0) {
      result.registrant = null;
    }
    if (result.adminContact && Object.keys(result.adminContact).length === 0) {
      result.adminContact = null;
    }
    if (result.techContact && Object.keys(result.techContact).length === 0) {
      result.techContact = null;
    }

    return result;
  }

  parseDate(dateString) {
    if (!dateString) return null;

    // Try to parse various date formats
    const formats = [
      /(\d{4})-(\d{2})-(\d{2})/,  // YYYY-MM-DD
      /(\d{2})-(\d{2})-(\d{4})/,  // MM-DD-YYYY or DD-MM-YYYY
      /(\d{4})\.(\d{2})\.(\d{2})/, // YYYY.MM.DD
      /(\d{2})\.(\d{2})\.(\d{4})/, // DD.MM.YYYY
    ];

    for (const format of formats) {
      const match = dateString.match(format);
      if (match) {
        try {
          // Try to create a valid date
          const date = new Date(dateString);
          if (!isNaN(date.getTime())) {
            return date.toISOString();
          }
        } catch (e) {
          continue;
        }
      }
    }

    return dateString; // Return original string if parsing fails
  }
}