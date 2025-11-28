import { RdapClient } from '../lib/rdap.js';
import { WhoisClient } from '../lib/whois.js';

export class DomainLookupTool {
  constructor() {
    this.rdapClient = new RdapClient();
    this.whoisClient = new WhoisClient();
  }

  getToolDefinition() {
    return {
      name: 'domain_lookup',
      description: 'Look up domain information using RDAP protocol with WHOIS fallback. Provides comprehensive domain registration details, nameservers, contacts, and status information.',
      inputSchema: {
        type: 'object',
        properties: {
          domain: {
            type: 'string',
            description: 'The domain name to look up (e.g., example.com)'
          },
          prefer_whois: {
            type: 'boolean',
            description: 'If true, use WHOIS instead of RDAP as the primary lookup method',
            default: false
          },
          include_raw: {
            type: 'boolean', 
            description: 'If true, include raw protocol response data in the result',
            default: false
          }
        },
        required: ['domain'],
        additionalProperties: false
      }
    };
  }

  async execute(params) {
    const { domain, prefer_whois = false, include_raw = false } = params;

    if (!domain) {
      throw new Error('Domain parameter is required');
    }

    let result;
    let primaryMethod = prefer_whois ? 'whois' : 'rdap';
    let fallbackMethod = prefer_whois ? 'rdap' : 'whois';

    try {
      // Try primary method first
      if (primaryMethod === 'rdap') {
        result = await this.rdapClient.lookupDomain(domain);
        result.method = 'rdap';
      } else {
        result = await this.whoisClient.lookupDomain(domain);
        result.method = 'whois';
      }

      // If primary method failed or didn't find the domain, try fallback
      if (!result.found && fallbackMethod) {
        console.log(`Primary method (${primaryMethod}) failed, trying fallback (${fallbackMethod})`);
        
        try {
          let fallbackResult;
          if (fallbackMethod === 'rdap') {
            fallbackResult = await this.rdapClient.lookupDomain(domain);
            fallbackResult.method = 'rdap';
          } else {
            fallbackResult = await this.whoisClient.lookupDomain(domain);
            fallbackResult.method = 'whois';
          }

          if (fallbackResult.found) {
            result = fallbackResult;
            result.fallback_used = true;
            result.primary_method_failed = primaryMethod;
          }
        } catch (fallbackError) {
          console.warn(`Fallback method also failed: ${fallbackError.message}`);
          result.fallback_error = fallbackError.message;
        }
      }

    } catch (error) {
      // If primary method throws an error, try fallback
      console.log(`Primary method (${primaryMethod}) threw error, trying fallback: ${error.message}`);
      
      try {
        if (fallbackMethod === 'rdap') {
          result = await this.rdapClient.lookupDomain(domain);
          result.method = 'rdap';
        } else {
          result = await this.whoisClient.lookupDomain(domain);
          result.method = 'whois';
        }
        
        result.fallback_used = true;
        result.primary_method_error = error.message;
        
      } catch (fallbackError) {
        // Both methods failed
        throw new Error(`Both RDAP and WHOIS lookups failed. RDAP: ${primaryMethod === 'rdap' ? error.message : fallbackError.message}, WHOIS: ${primaryMethod === 'whois' ? error.message : fallbackError.message}`);
      }
    }

    // Clean up result for output
    return this.formatResult(result, include_raw);
  }

  formatResult(result, includeRaw) {
    const formatted = {
      domain: result.domain,
      found: result.found,
      method: result.method,
      timestamp: new Date().toISOString()
    };

    if (result.fallback_used) {
      formatted.fallback_used = result.fallback_used;
      formatted.primary_method_failed = result.primary_method_failed;
    }

    if (result.primary_method_error) {
      formatted.primary_method_error = result.primary_method_error;
    }

    if (result.fallback_error) {
      formatted.fallback_error = result.fallback_error;
    }

    if (!result.found) {
      formatted.message = result.message || result.error || 'Domain not found';
      return formatted;
    }

    // Add common fields regardless of method
    if (result.status && result.status.length > 0) {
      formatted.status = result.status;
    }

    if (result.nameservers && result.nameservers.length > 0) {
      formatted.nameservers = result.nameservers;
    }

    // Format based on method
    if (result.method === 'rdap') {
      formatted.rdap = this.formatRdapResult(result);
    } else {
      formatted.whois = this.formatWhoisResult(result);
    }

    // Include raw data if requested
    if (includeRaw && result.rawData) {
      formatted.raw_data = result.rawData;
    }

    return formatted;
  }

  formatRdapResult(result) {
    const rdap = {
      conformance: result.rdapConformance,
      object_class: result.objectClassName,
      handle: result.handle
    };

    // Events/dates
    if (result.events && result.events.length > 0) {
      rdap.events = result.events;
    }

    if (result.registrationDate) rdap.registration_date = result.registrationDate;
    if (result.expirationDate) rdap.expiration_date = result.expirationDate;
    if (result.lastChangedDate) rdap.last_changed_date = result.lastChangedDate;

    // Entities (contacts)
    if (result.entities && result.entities.length > 0) {
      rdap.contacts = result.entities.map(entity => ({
        handle: entity.handle,
        roles: entity.roles,
        contact_info: entity.contact
      }));
    }

    // Nameservers (more detailed than the common field)
    if (result.nameservers && result.nameservers.length > 0) {
      rdap.nameserver_details = result.nameservers;
    }

    // Security
    if (result.secureDNS) {
      rdap.dnssec = result.secureDNS;
    }

    // Additional info
    if (result.remarks && result.remarks.length > 0) {
      rdap.remarks = result.remarks;
    }

    if (result.links && result.links.length > 0) {
      rdap.links = result.links;
    }

    if (result.port43) {
      rdap.whois_server = result.port43;
    }

    return rdap;
  }

  formatWhoisResult(result) {
    const whois = {};

    if (result.registrar) whois.registrar = result.registrar;
    
    if (result.registrant) whois.registrant = result.registrant;
    if (result.adminContact) whois.admin_contact = result.adminContact;
    if (result.techContact) whois.technical_contact = result.techContact;
    if (result.billingContact) whois.billing_contact = result.billingContact;

    if (result.dates && Object.keys(result.dates).length > 0) {
      whois.dates = result.dates;
    }

    if (result.dnssec) whois.dnssec = result.dnssec;

    return whois;
  }
}