import express from 'express';
import path from 'path';
import { setupNyloRoutes } from '../server';

const app = express();
app.use(express.json());

app.use(express.static(path.join(__dirname, '.')));

app.get('/nylo.js', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'src', 'nylo.js'));
});

const interactions: any[] = [];

const customers = [
  { id: 1, name: 'Demo Customer', apiKey: 'demo_api_key_12345678' }
];

const domainVerifications: Map<string, any> = new Map();

function verificationKey(domain: string, customerId: number): string {
  return `${domain}:${customerId}`;
}

const storage = {
  async createInteraction(data: any) {
    const interaction = { id: interactions.length + 1, ...data, createdAt: new Date() };
    interactions.push(interaction);
    console.log(`[Nylo] Event: ${data.interactionType} | Domain: ${data.domain} | WaiTag: ${data.userId || 'anonymous'}`);
    return interaction;
  },

  async getCustomer(id: number) {
    return customers.find(c => c.id === id) || null;
  },

  async getCustomerByApiKey(apiKey: string) {
    return customers.find(c => c.apiKey === apiKey) || null;
  },

  parseDomain(domain: string) {
    const parts = domain.split('.');
    if (parts.length > 2) {
      return { mainDomain: parts.slice(1).join('.'), subdomain: parts[0] };
    }
    return { mainDomain: domain, subdomain: null };
  },

  async getDomainVerification(domain: string, customerId: number) {
    return domainVerifications.get(verificationKey(domain, customerId)) || null;
  },

  async createDomainVerification(data: { domain: string; customerId: number; token: string; status: string }) {
    const record = { ...data, createdAt: new Date() };
    domainVerifications.set(verificationKey(data.domain, data.customerId), record);
    console.log(`[Nylo] Domain verification requested: ${data.domain} (token: ${data.token})`);
    return record;
  },

  async updateDomainVerification(domain: string, customerId: number, data: any) {
    const key = verificationKey(domain, customerId);
    const existing = domainVerifications.get(key);
    if (existing) {
      const updated = { ...existing, ...data };
      domainVerifications.set(key, updated);
      if (data.status === 'verified') {
        console.log(`[Nylo] Domain verified: ${domain}`);
      }
      return updated;
    }
    return null;
  },

  async isDomainVerified(domain: string, customerId: number) {
    const record = domainVerifications.get(verificationKey(domain, customerId));
    return record?.status === 'verified';
  }
};

setupNyloRoutes(app, storage);

app.get('/api/events', (req, res) => {
  res.json({
    total: interactions.length,
    events: interactions.slice(-50)
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Nylo example server running at http://localhost:${PORT}`);
  console.log(`Open http://localhost:${PORT}/basic.html to see tracking in action`);
  console.log(`View collected events at http://localhost:${PORT}/api/events`);
});
