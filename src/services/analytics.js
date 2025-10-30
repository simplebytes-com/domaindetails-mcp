export class AnalyticsService {
  constructor(kv) {
    this.kv = kv;
  }

  async trackLookup(params) {
    try {
      const {
        domain,
        method,
        found,
        source,
        transport,
        userAgent,
        timestamp = new Date().toISOString()
      } = params;

      // Create lookup record
      const lookupRecord = {
        domain: domain.toLowerCase(),
        method,
        found,
        source,
        transport,
        userAgent,
        timestamp
      };

      // Store individual lookup with unique ID
      const lookupId = `lookup:${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      await this.kv.put(lookupId, JSON.stringify(lookupRecord), {
        expirationTtl: 30 * 24 * 60 * 60 // 30 days
      });

      // Update daily stats
      await this.updateDailyStats(lookupRecord);

      // Update domain-specific stats
      await this.updateDomainStats(domain, method);

    } catch (error) {
      // Don't let analytics errors affect the main request
      console.error('Analytics error:', error);
    }
  }

  async updateDailyStats(lookupRecord) {
    const today = new Date().toISOString().split('T')[0];
    const statsKey = `stats:daily:${today}`;

    try {
      const existing = await this.kv.get(statsKey, 'json') || {
        date: today,
        total: 0,
        byMethod: { rdap: 0, whois: 0 },
        byTransport: {},
        uniqueDomains: new Set(),
        byStatus: { found: 0, notFound: 0 }
      };

      // Update stats
      existing.total++;
      existing.byMethod[lookupRecord.method] = (existing.byMethod[lookupRecord.method] || 0) + 1;
      existing.byTransport[lookupRecord.transport] = (existing.byTransport[lookupRecord.transport] || 0) + 1;
      
      if (lookupRecord.found) {
        existing.byStatus.found++;
      } else {
        existing.byStatus.notFound++;
      }

      // Convert Set to Array for storage
      const domains = Array.from(existing.uniqueDomains || []);
      if (!domains.includes(lookupRecord.domain)) {
        domains.push(lookupRecord.domain);
      }
      existing.uniqueDomains = domains;
      existing.uniqueCount = domains.length;

      await this.kv.put(statsKey, JSON.stringify(existing), {
        expirationTtl: 90 * 24 * 60 * 60 // 90 days
      });
    } catch (error) {
      console.error('Failed to update daily stats:', error);
    }
  }

  async updateDomainStats(domain, method) {
    const domainKey = `domain:${domain.toLowerCase()}`;

    try {
      const existing = await this.kv.get(domainKey, 'json') || {
        domain: domain.toLowerCase(),
        firstSeen: new Date().toISOString(),
        lookupCount: 0,
        lastLookup: null,
        methods: { rdap: 0, whois: 0 }
      };

      existing.lookupCount++;
      existing.lastLookup = new Date().toISOString();
      existing.methods[method] = (existing.methods[method] || 0) + 1;

      await this.kv.put(domainKey, JSON.stringify(existing), {
        expirationTtl: 365 * 24 * 60 * 60 // 1 year
      });
    } catch (error) {
      console.error('Failed to update domain stats:', error);
    }
  }

  async getStats(range = 'today') {
    try {
      if (range === 'today') {
        const today = new Date().toISOString().split('T')[0];
        return await this.kv.get(`stats:daily:${today}`, 'json') || { date: today, total: 0 };
      }

      if (range === 'week') {
        const stats = [];
        const today = new Date();
        
        for (let i = 0; i < 7; i++) {
          const date = new Date(today);
          date.setDate(date.getDate() - i);
          const dateStr = date.toISOString().split('T')[0];
          const dayStats = await this.kv.get(`stats:daily:${dateStr}`, 'json');
          if (dayStats) {
            stats.push(dayStats);
          }
        }

        return this.aggregateStats(stats);
      }

      if (range === 'month') {
        const stats = [];
        const today = new Date();
        
        for (let i = 0; i < 30; i++) {
          const date = new Date(today);
          date.setDate(date.getDate() - i);
          const dateStr = date.toISOString().split('T')[0];
          const dayStats = await this.kv.get(`stats:daily:${dateStr}`, 'json');
          if (dayStats) {
            stats.push(dayStats);
          }
        }

        return this.aggregateStats(stats);
      }

      // Get top domains
      if (range === 'top-domains') {
        const list = await this.kv.list({ prefix: 'domain:', limit: 1000 });
        const domains = [];

        for (const key of list.keys) {
          const data = await this.kv.get(key.name, 'json');
          if (data) {
            domains.push(data);
          }
        }

        return domains
          .sort((a, b) => b.lookupCount - a.lookupCount)
          .slice(0, 10);
      }

      return { error: 'Invalid range' };
    } catch (error) {
      console.error('Failed to get stats:', error);
      return { error: error.message };
    }
  }

  aggregateStats(dailyStats) {
    const aggregate = {
      period: `${dailyStats.length} days`,
      total: 0,
      byMethod: { rdap: 0, whois: 0 },
      byTransport: {},
      uniqueDomains: new Set(),
      byStatus: { found: 0, notFound: 0 },
      dailyBreakdown: []
    };

    for (const day of dailyStats) {
      aggregate.total += day.total;
      aggregate.byMethod.rdap += day.byMethod.rdap || 0;
      aggregate.byMethod.whois += day.byMethod.whois || 0;
      aggregate.byStatus.found += day.byStatus.found || 0;
      aggregate.byStatus.notFound += day.byStatus.notFound || 0;

      // Merge transport stats
      for (const [transport, count] of Object.entries(day.byTransport || {})) {
        aggregate.byTransport[transport] = (aggregate.byTransport[transport] || 0) + count;
      }

      // Merge unique domains
      if (day.uniqueDomains) {
        for (const domain of day.uniqueDomains) {
          aggregate.uniqueDomains.add(domain);
        }
      }

      aggregate.dailyBreakdown.push({
        date: day.date,
        total: day.total,
        uniqueDomains: day.uniqueCount || (day.uniqueDomains ? day.uniqueDomains.length : 0)
      });
    }

    aggregate.uniqueCount = aggregate.uniqueDomains.size;
    aggregate.uniqueDomains = Array.from(aggregate.uniqueDomains).slice(0, 100); // Limit to 100 for response size

    return aggregate;
  }
}