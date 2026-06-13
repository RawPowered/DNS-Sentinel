import dns from 'node:dns/promises';
import type { Request, Response } from 'express';
import { saveAudit } from './db.js';
import { detectEmailProvider } from './emailAudit.js';
import {
  detectVite,
  detectWordPress,
  runDeepViteScan,
  runSslAndHeadersCheck,
  scanExposures,
} from './frameworkDetect.js';

function calculateScore(results: any, emailHealth: any, hasMultipleSpf: boolean) {
  let score = 100;
  if (!results.ssl.valid) score -= 30;
  if (!results.security.headers.hsts) score -= 10;
  if (!results.security.headers.csp) score -= 10;
  if (!results.security.headers.xfo) score -= 5;
  if (!results.security.headers.referrer) score -= 5;
  if (!results.security.headers.permissions) score -= 5;

  const criticalExposures = ['.env', '.git/config', 'wp-config.php.bak', 'package.json', 'vite.config.ts', 'src/main.ts'];
  results.security.exposures.forEach((exp: string) => {
    if (criticalExposures.includes(exp)) score -= 20;
    else if (exp === 'assets/' || exp === 'dist/assets/') score -= 10;
    else if (exp === 'manifest.json') score -= 5;
    else if (exp.startsWith('dist/')) score -= 8;
  });

  if (results.dns.mx.length > 0 && !results.dns.spf) score -= 10;
  if (results.dns.mx.length > 0 && !results.dns.dmarc) score -= 10;
  if (hasMultipleSpf) score -= 20;
  if (emailHealth.issues.some((i: string) => i.includes('Missing') && i.includes('SPF include'))) score -= 15;
  if (results.security.serverHeader) score -= 5;

  return Math.max(0, score);
}

export async function analyzeDomain(domain: string, deepViteScan = false) {
  const results: any = {
    domain,
    dns: { spf: null, dmarc: null },
    ssl: null,
    wordpress: null,
    vite: null,
    hosting: null,
    security: { headers: {}, exposures: [], serverHeader: null },
  };

  const [aRecords, mxRecords, nsRecords, txtRecords] = await Promise.allSettled([
    dns.resolve4(domain),
    dns.resolveMx(domain),
    dns.resolveNs(domain),
    dns.resolveTxt(domain),
  ]);

  results.dns.a = aRecords.status === 'fulfilled' ? aRecords.value : [];
  results.dns.mx = mxRecords.status === 'fulfilled' ? mxRecords.value : [];
  results.dns.ns = nsRecords.status === 'fulfilled' ? nsRecords.value : [];
  const txts = txtRecords.status === 'fulfilled' ? txtRecords.value.flat() : [];
  results.dns.txt = txts;

  const spfRecords = txts.filter((t: string) => t.toLowerCase().startsWith('v=spf1'));
  results.dns.spf = spfRecords[0] || null;
  const hasMultipleSpf = spfRecords.length > 1;

  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
    results.dns.dmarc = dmarcRecords.flat().find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null;
  } catch {
    results.dns.dmarc = null;
  }

  const emailHealth = detectEmailProvider(results.dns.mx, results.dns.spf, results.dns.dmarc, hasMultipleSpf);
  if (results.dns.mx.length === 0) {
    emailHealth.issues = ['No MX records found. Email delivery is disabled.'];
    emailHealth.status = 'error';
  }
  results.emailHealth = emailHealth;

  const [securityCheck, exposures, wpRes, viteRes] = await Promise.all([
    runSslAndHeadersCheck(domain),
    scanExposures(domain, deepViteScan),
    detectWordPress(domain),
    detectVite(domain),
  ]);

  results.ssl = securityCheck.ssl;
  results.security.headers = securityCheck.headers;
  results.security.serverHeader = securityCheck.server;
  results.security.exposures = exposures;
  results.wordpress = wpRes;
  results.vite = {
    ...viteRes,
    deepScan: deepViteScan ? await runDeepViteScan(domain) : { enabled: false, paths: [], findings: [] },
  };

  const nsList = results.dns.ns.map((ns: string) => ns.toLowerCase());
  results.hosting = {
    isNamecheap: nsList.some((ns: string) => ns.includes('namecheap') || ns.includes('registrar-servers.com')),
    isGoDaddy: nsList.some((ns: string) => ns.includes('domaincontrol.com')),
    nameservers: results.dns.ns,
  };

  results.score = calculateScore(results, emailHealth, hasMultipleSpf);
  return results;
}

export async function analyzeHandler(req: Request, res: Response) {
  const { domain, deepViteScan } = req.body;
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const results = await analyzeDomain(domain, Boolean(deepViteScan));
    saveAudit(domain, results.score, results);
    res.json(results);
  } catch (error: any) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze domain', details: error.message });
  }
}
