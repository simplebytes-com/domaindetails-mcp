/**
 * DomainDetails - Domain information lookup library
 *
 * Provides comprehensive domain research using RDAP protocol with WHOIS fallback.
 *
 * @example
 * // Simple lookup
 * import { lookup } from 'domaindetails';
 * const result = await lookup('example.com');
 *
 * @example
 * // With options
 * import { DomainLookup } from 'domaindetails';
 * const client = new DomainLookup();
 * const result = await client.lookup('example.com', { preferWhois: true });
 */

import { RdapClient } from './lib/rdap.js';
import { WhoisClient } from './lib/whois.js';

/**
 * DomainLookup class for comprehensive domain information retrieval
 */
export class DomainLookup {
  constructor() {
    this.rdapClient = new RdapClient();
    this.whoisClient = new WhoisClient();
  }

  /**
   * Look up domain information using RDAP with WHOIS fallback
   * @param {string} domain - The domain name to look up (e.g., 'example.com')
   * @param {Object} options - Lookup options
   * @param {boolean} [options.preferWhois=false] - Use WHOIS instead of RDAP as primary method
   * @param {boolean} [options.includeRaw=false] - Include raw protocol response data
   * @returns {Promise<Object>} Domain information object
   */
  async lookup(domain, options = {}) {
    const { preferWhois = false, includeRaw = false } = options;

    if (!domain) {
      throw new Error('Domain parameter is required');
    }

    let result;
    let primaryMethod = preferWhois ? 'whois' : 'rdap';
    let fallbackMethod = preferWhois ? 'rdap' : 'whois';

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
          result.fallback_error = fallbackError.message;
        }
      }

    } catch (error) {
      // If primary method throws an error, try fallback
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

    return this.formatResult(result, includeRaw);
  }

  /**
   * Look up domain using RDAP only
   * @param {string} domain - The domain name to look up
   * @param {Object} options - Lookup options
   * @param {boolean} [options.includeRaw=false] - Include raw protocol response data
   * @returns {Promise<Object>} Domain information object
   */
  async rdap(domain, options = {}) {
    const { includeRaw = false } = options;

    if (!domain) {
      throw new Error('Domain parameter is required');
    }

    const result = await this.rdapClient.lookupDomain(domain);
    result.method = 'rdap';
    return this.formatResult(result, includeRaw);
  }

  /**
   * Look up domain using WHOIS only
   * @param {string} domain - The domain name to look up
   * @param {Object} options - Lookup options
   * @param {boolean} [options.includeRaw=false] - Include raw protocol response data
   * @returns {Promise<Object>} Domain information object
   */
  async whois(domain, options = {}) {
    const { includeRaw = false } = options;

    if (!domain) {
      throw new Error('Domain parameter is required');
    }

    const result = await this.whoisClient.lookupDomain(domain);
    result.method = 'whois';
    return this.formatResult(result, includeRaw);
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

/**
 * Simple lookup function for quick domain lookups
 * @param {string} domain - The domain name to look up
 * @param {Object} options - Lookup options
 * @returns {Promise<Object>} Domain information object
 */
export async function lookup(domain, options = {}) {
  const client = new DomainLookup();
  return client.lookup(domain, options);
}

/**
 * RDAP-only lookup
 * @param {string} domain - The domain name to look up
 * @param {Object} options - Lookup options
 * @returns {Promise<Object>} Domain information object
 */
export async function rdap(domain, options = {}) {
  const client = new DomainLookup();
  return client.rdap(domain, options);
}

/**
 * WHOIS-only lookup
 * @param {string} domain - The domain name to look up
 * @param {Object} options - Lookup options
 * @returns {Promise<Object>} Domain information object
 */
export async function whois(domain, options = {}) {
  const client = new DomainLookup();
  return client.whois(domain, options);
}

// Export the underlying clients for advanced usage
export { RdapClient } from './lib/rdap.js';
export { WhoisClient } from './lib/whois.js';
export { RegistryDetector } from './services/registry-detector.js';

// Default export
export default { DomainLookup, lookup, rdap, whois };
