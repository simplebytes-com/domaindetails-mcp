import { RegistryDetector } from '../services/registry-detector.js';

export class RdapClient {
  constructor() {
    this.registryDetector = new RegistryDetector();
    this.timeout = 10000; // 10 seconds timeout
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
      const rdapUrl = await this.registryDetector.getRdapUrl(cleanDomain);
      
      if (!rdapUrl) {
        throw new Error(`No RDAP server found for domain: ${cleanDomain}`);
      }

      const queryUrl = `${rdapUrl}domain/${cleanDomain}`;
      
      const response = await fetch(queryUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/rdap+json,application/json',
          'User-Agent': 'RDAP-MCP-Server/1.0.0'
        },
        signal: AbortSignal.timeout(this.timeout)
      });

      if (!response.ok) {
        if (response.status === 404) {
          return {
            domain: cleanDomain,
            found: false,
            status: 'not_found',
            message: 'Domain not found in registry'
          };
        }
        
        throw new Error(`RDAP query failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      return this.parseRdapResponse(data, cleanDomain);
      
    } catch (error) {
      if (error.name === 'TimeoutError') {
        throw new Error(`RDAP query timed out after ${this.timeout}ms`);
      }
      throw error;
    }
  }

  parseRdapResponse(data, domain) {
    const result = {
      domain,
      found: true,
      lookupStatus: 'found',
      rdapConformance: data.rdapConformance || [],
      objectClassName: data.objectClassName,
      ldhName: data.ldhName || domain,
      unicodeName: data.unicodeName,
      handle: data.handle,
      status: data.status || [],
      events: [],
      entities: [],
      nameservers: [],
      secureDNS: data.secureDNS,
      remarks: data.remarks || [],
      links: data.links || [],
      port43: data.port43,
      rawData: data
    };

    // Parse events
    if (data.events) {
      result.events = data.events.map(event => ({
        eventAction: event.eventAction,
        eventDate: event.eventDate,
        eventActor: event.eventActor
      }));
    }

    // Parse entities (registrant, admin, tech, etc.)
    if (data.entities) {
      result.entities = data.entities.map(entity => this.parseEntity(entity));
    }

    // Parse nameservers
    if (data.nameservers) {
      result.nameservers = data.nameservers.map(ns => ({
        ldhName: ns.ldhName,
        unicodeName: ns.unicodeName,
        ipAddresses: ns.ipAddresses,
        status: ns.status
      }));
    }

    // Extract common registration dates
    const registrationEvent = data.events?.find(e => e.eventAction === 'registration');
    const expirationEvent = data.events?.find(e => e.eventAction === 'expiration');
    const lastChangedEvent = data.events?.find(e => e.eventAction === 'last changed');

    if (registrationEvent) {
      result.registrationDate = registrationEvent.eventDate;
    }
    if (expirationEvent) {
      result.expirationDate = expirationEvent.eventDate;
    }
    if (lastChangedEvent) {
      result.lastChangedDate = lastChangedEvent.eventDate;
    }

    return result;
  }

  parseEntity(entity) {
    const parsed = {
      handle: entity.handle,
      roles: entity.roles || [],
      vcardArray: entity.vcardArray,
      status: entity.status,
      remarks: entity.remarks,
      links: entity.links,
      events: entity.events,
      publicIds: entity.publicIds
    };

    // Parse vCard if available
    if (entity.vcardArray && entity.vcardArray.length > 1) {
      const vcard = entity.vcardArray[1];
      parsed.contact = this.parseVCard(vcard);
    }

    return parsed;
  }

  parseVCard(vcard) {
    const contact = {};

    if (!Array.isArray(vcard)) return contact;

    for (const field of vcard) {
      if (!Array.isArray(field) || field.length < 4) continue;

      const [property, params, type, value] = field;

      switch (property.toLowerCase()) {
        case 'fn':
          contact.name = value;
          break;
        case 'org':
          contact.organization = Array.isArray(value) ? value[0] : value;
          break;
        case 'email':
          if (!contact.emails) contact.emails = [];
          contact.emails.push(value);
          break;
        case 'tel':
          if (!contact.phones) contact.phones = [];
          contact.phones.push({
            type: params?.type || 'voice',
            value: value
          });
          break;
        case 'adr':
          if (!contact.addresses) contact.addresses = [];
          if (Array.isArray(value) && value.length >= 7) {
            contact.addresses.push({
              type: params?.type || 'postal',
              poBox: value[0],
              extendedAddress: value[1],
              streetAddress: value[2],
              locality: value[3],
              region: value[4],
              postalCode: value[5],
              country: value[6]
            });
          }
          break;
      }
    }

    return contact;
  }
}