export class RegistryDetector {
  constructor() {
    this.rdapBootstrap = new Map([
      // Generic TLDs
      ['com', 'https://rdap.verisign.com/com/v1/'],
      ['net', 'https://rdap.verisign.com/net/v1/'],
      ['org', 'https://rdap.pir.org/'],
      ['info', 'https://rdap.afilias.info/rdap/'],
      ['biz', 'https://rdap.afilias.info/rdap/'],
      ['name', 'https://rdap.verisign.com/name/v1/'],
      ['pro', 'https://rdap.afilias.info/rdap/'],
      
      // Country code TLDs
      ['uk', 'https://rdap.nominet.uk/'],
      ['co.uk', 'https://rdap.nominet.uk/'],
      ['org.uk', 'https://rdap.nominet.uk/'],
      ['me.uk', 'https://rdap.nominet.uk/'],
      ['ltd.uk', 'https://rdap.nominet.uk/'],
      ['plc.uk', 'https://rdap.nominet.uk/'],
      ['ca', 'https://rdap.cira.ca/'],
      ['au', 'https://rdap.auda.org.au/'],
      ['com.au', 'https://rdap.auda.org.au/'],
      ['net.au', 'https://rdap.auda.org.au/'],
      ['org.au', 'https://rdap.auda.org.au/'],
      ['edu.au', 'https://rdap.auda.org.au/'],
      ['de', 'https://rdap.denic.de/'],
      ['fr', 'https://rdap.nic.fr/'],
      ['nl', 'https://rdap.sidn.nl/'],
      ['be', 'https://rdap.dns.be/'],
      ['ch', 'https://rdap.nic.ch/'],
      ['at', 'https://rdap.nic.at/'],
      ['it', 'https://rdap.nic.it/'],
      ['es', 'https://rdap.nic.es/'],
      ['se', 'https://rdap.iis.se/'],
      ['no', 'https://rdap.norid.no/'],
      ['dk', 'https://rdap.dk-hostmaster.dk/'],
      ['fi', 'https://rdap.ficora.fi/'],
      ['ie', 'https://rdap.weare.ie/'],
      ['pl', 'https://rdap.dns.pl/'],
      ['cz', 'https://rdap.nic.cz/'],
      ['sk', 'https://rdap.sk-nic.sk/'],
      ['hu', 'https://rdap.nic.hu/'],
      ['ro', 'https://rdap.rotld.ro/'],
      ['bg', 'https://rdap.register.bg/'],
      ['hr', 'https://rdap.dns.hr/'],
      ['si', 'https://rdap.register.si/'],
      ['lv', 'https://rdap.nic.lv/'],
      ['lt', 'https://rdap.domreg.lt/'],
      ['ee', 'https://rdap.internet.ee/'],
      
      // New gTLDs (common ones)
      ['xyz', 'https://rdap.centralnic.com/xyz/'],
      ['top', 'https://rdap.nic.top/'],
      ['site', 'https://rdap.centralnic.com/site/'],
      ['online', 'https://rdap.centralnic.com/online/'],
      ['tech', 'https://rdap.nic.tech/'],
      ['store', 'https://rdap.nic.store/'],
      ['app', 'https://rdap.charleston.com/'],
      ['dev', 'https://rdap.charleston.com/'],
      ['io', 'https://rdap.nic.io/'],
      ['ai', 'https://rdap.nic.ai/'],
      ['co', 'https://rdap.nic.co/'],
      ['me', 'https://rdap.nic.me/'],
      ['tv', 'https://rdap.nic.tv/'],
      ['cc', 'https://rdap.nic.cc/'],
    ]);
    
    this.ianaTlds = null;
    this.lastBootstrapUpdate = null;
  }

  async getTLD(domain) {
    if (!domain || typeof domain !== 'string') {
      throw new Error('Invalid domain provided');
    }
    
    const parts = domain.toLowerCase().split('.');
    if (parts.length < 2) {
      throw new Error('Invalid domain format');
    }
    
    // Handle second-level domains (like .co.uk, .com.au, etc.)
    const commonSecondLevel = new Set([
      'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk',
      'com.au', 'net.au', 'org.au', 'edu.au',
      'co.nz', 'net.nz', 'org.nz',
      'co.za', 'net.za', 'org.za',
      'co.in', 'net.in', 'org.in',
      'com.br', 'net.br', 'org.br',
      'co.jp', 'or.jp', 'ne.jp'
    ]);
    
    if (parts.length >= 3) {
      const secondLevel = parts.slice(-2).join('.');
      if (commonSecondLevel.has(secondLevel)) {
        return secondLevel;
      }
    }
    
    return parts[parts.length - 1];
  }

  async getRdapUrl(domain) {
    const tld = await this.getTLD(domain);
    
    // Check our static bootstrap map first
    if (this.rdapBootstrap.has(tld)) {
      return this.rdapBootstrap.get(tld);
    }
    
    // Try to fetch from IANA bootstrap service as fallback
    try {
      const bootstrapUrl = `https://data.iana.org/rdap/dns.json`;
      const response = await fetch(bootstrapUrl);
      
      if (response.ok) {
        const data = await response.json();
        const services = data.services || [];
        
        for (const service of services) {
          const [tlds, urls] = service;
          if (tlds.includes(tld) && urls.length > 0) {
            // Cache the result
            this.rdapBootstrap.set(tld, urls[0]);
            return urls[0];
          }
        }
      }
    } catch (error) {
      console.warn(`Failed to fetch IANA bootstrap data: ${error.message}`);
    }
    
    return null;
  }

  async getWhoisServer(domain) {
    const tld = await this.getTLD(domain);
    
    const whoisServers = new Map([
      ['com', 'whois.verisign-grs.com'],
      ['net', 'whois.verisign-grs.com'],
      ['org', 'whois.pir.org'],
      ['info', 'whois.afilias.net'],
      ['biz', 'whois.afilias.net'],
      ['name', 'whois.nic.name'],
      ['pro', 'whois.afilias.net'],
      ['uk', 'whois.nic.uk'],
      ['co.uk', 'whois.nic.uk'],
      ['org.uk', 'whois.nic.uk'],
      ['me.uk', 'whois.nic.uk'],
      ['ltd.uk', 'whois.nic.uk'],
      ['plc.uk', 'whois.nic.uk'],
      ['ca', 'whois.cira.ca'],
      ['au', 'whois.aunic.net'],
      ['com.au', 'whois.aunic.net'],
      ['net.au', 'whois.aunic.net'],
      ['org.au', 'whois.aunic.net'],
      ['edu.au', 'whois.aunic.net'],
      ['de', 'whois.denic.de'],
      ['fr', 'whois.nic.fr'],
      ['nl', 'whois.domain-registry.nl'],
      ['be', 'whois.dns.be'],
      ['ch', 'whois.nic.ch'],
      ['at', 'whois.nic.at'],
      ['it', 'whois.nic.it'],
      ['es', 'whois.nic.es'],
      ['se', 'whois.iis.se'],
      ['no', 'whois.norid.no'],
      ['dk', 'whois.dk-hostmaster.dk'],
      ['fi', 'whois.ficora.fi'],
      ['ie', 'whois.weare.ie'],
      ['pl', 'whois.dns.pl'],
      ['cz', 'whois.nic.cz'],
      ['sk', 'whois.sk-nic.sk'],
      ['hu', 'whois.nic.hu'],
      ['ro', 'whois.rotld.ro'],
      ['bg', 'whois.register.bg'],
      ['hr', 'whois.dns.hr'],
      ['si', 'whois.register.si'],
      ['lv', 'whois.nic.lv'],
      ['lt', 'whois.domreg.lt'],
      ['ee', 'whois.tld.ee'],
      ['xyz', 'whois.nic.xyz'],
      ['top', 'whois.nic.top'],
      ['site', 'whois.centralnic.com'],
      ['online', 'whois.centralnic.com'],
      ['tech', 'whois.nic.tech'],
      ['store', 'whois.nic.store'],
      ['io', 'whois.nic.io'],
      ['ai', 'whois.nic.ai'],
      ['co', 'whois.nic.co'],
      ['me', 'whois.nic.me'],
      ['tv', 'whois.nic.tv'],
      ['cc', 'whois.nic.cc'],
    ]);
    
    return whoisServers.get(tld) || 'whois.iana.org';
  }
}