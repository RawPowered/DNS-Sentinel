import { GoogleGenAI } from '@google/genai';
import type { Express, Request, Response } from 'express';

export const GEMINI_MODEL = 'gemini-3.1-pro-preview';

function getClient() {
  const apiKey = process.env.GEMINI_API_KEY || process.env.API_KEY;
  if (!apiKey) throw new Error('GEMINI_API_KEY is not configured on the server.');
  return new GoogleGenAI({ apiKey });
}

function stackContext(audit: any) {
  const stack = audit.wordpress?.detected
    ? 'WordPress'
    : audit.vite?.detected
      ? 'Vite/static SPA build'
      : 'Custom stack';
  const hosting = audit.hosting?.isNamecheap
    ? 'Namecheap nameservers'
    : audit.hosting?.isGoDaddy
      ? 'GoDaddy nameservers'
      : `Nameservers: ${(audit.hosting?.nameservers || []).join(', ') || 'unknown'}`;
  return `${stack} on ${hosting}`;
}

export function registerAiRoutes(app: Express) {
  app.post('/api/ai/fix-guide', async (req: Request, res: Response) => {
    try {
      const { audit } = req.body;
      if (!audit?.domain) {
        return res.status(400).json({ error: 'Audit result with domain is required' });
      }

      const ai = getClient();
      const response = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: `Provide a detailed FIX GUIDE for the following domain audit results: "${audit.domain}".

CONTEXT: ${stackContext(audit)}

Data:
${JSON.stringify(audit, null, 2)}

Focus ONLY on:
1. Step-by-step instructions to fix the detected security and DNS issues (especially email migration MX/SPF/DMARC if relevant).
2. Code snippets for .htaccess, nginx, or DNS record examples.
3. Explanations for WHY these fixes are necessary.`,
      });

      res.json({ text: response.text || '' });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/ai/security-chat', async (req: Request, res: Response) => {
    try {
      const { audit, message, history } = req.body;
      if (!audit?.domain || !message) {
        return res.status(400).json({ error: 'Audit and message are required' });
      }

      const ai = getClient();
      const historyText = (history || [])
        .map((m: { role: string; text: string }) => `${m.role}: ${m.text}`)
        .join('\n');

      const response = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: `You are a DNS and Web Security expert helping with audit results for "${audit.domain}".
Stack context: ${stackContext(audit)}

Audit data:
${JSON.stringify(audit, null, 2)}

Prior conversation:
${historyText}

User question: ${message}

Keep answers technical, concise, and actionable for WordPress, Vite dist deployments, and registrar DNS panels.`,
      });

      res.json({ text: response.text || '' });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/ai/mx-chat', async (req: Request, res: Response) => {
    try {
      const { message, smtpResult, mxResult, emailAuditResult, history } = req.body;
      if (!message) {
        return res.status(400).json({ error: 'Message is required' });
      }

      const ai = getClient();
      const historyText = (history || [])
        .map((m: { role: string; text: string }) => `${m.role}: ${m.text}`)
        .join('\n');

      const response = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: `You are an expert Email Server Diagnostic AI (MXToolbox-style). Help troubleshoot SMTP, MX, SPF, and DMARC issues — especially Microsoft 365 to Google Workspace migrations.

Context:
SMTP Test: ${smtpResult ? JSON.stringify(smtpResult) : 'Not run'}
MX Reachability: ${mxResult ? JSON.stringify(mxResult) : 'Not run'}
Email Health Audit: ${emailAuditResult ? JSON.stringify(emailAuditResult) : 'Not run'}

Prior conversation:
${historyText}

User question: ${message}`,
      });

      res.json({ text: response.text || '' });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });
}
