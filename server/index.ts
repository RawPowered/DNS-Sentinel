import 'dotenv/config';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import { getHistory, getProfiles } from './db.js';
import { analyzeHandler } from './dnsAudit.js';
import { emailAuditHandler, testMx, testSmtp } from './emailAudit.js';
import { registerAiRoutes } from './aiRoutes.js';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  app.get('/api/history/:domain', (req, res) => {
    res.json(getHistory(req.params.domain));
  });

  app.get('/api/profiles', (_req, res) => {
    res.json(getProfiles());
  });

  app.post('/api/email/test-smtp', testSmtp);
  app.post('/api/email/test-mx', testMx);
  app.post('/api/email/audit', emailAuditHandler);
  app.post('/api/analyze', analyzeHandler);

  registerAiRoutes(app);

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`DNS-Sentinel running on http://localhost:${PORT}`);
  });
}

startServer();
