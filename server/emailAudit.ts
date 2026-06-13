import dns from 'node:dns/promises';
import net from 'node:net';
import nodemailer from 'nodemailer';
import type { Request, Response } from 'express';

export type EmailHealth = {
  domain?: string;
  provider: string;
  status: 'optimal' | 'error' | 'neutral';
  issues: string[];
  mx?: { exchange: string; priority: number }[];
  spf?: string | null;
  dmarc?: string | null;
  txt?: string[];
};

export function detectEmailProvider(
  mx: { exchange: string; priority: number }[],
  spf: string | null,
  dmarc: string | null,
  hasMultipleSpf = false,
): EmailHealth {
  const emailHealth: EmailHealth = {
    provider: 'None',
    status: 'neutral',
    issues: [],
  };

  if (mx.length === 0) {
    emailHealth.issues.push('No MX records found. Domain cannot receive email.');
    emailHealth.status = 'error';
    return emailHealth;
  }

  const mxString = mx.map((m) => m.exchange.toLowerCase()).join(' ');
  const spfString = spf ? spf.toLowerCase() : '';

  if (mxString.includes('google.com')) {
    emailHealth.provider = 'Google Workspace / Gmail';
    if (!spfString.includes('_spf.google.com')) {
      emailHealth.issues.push('Missing Google SPF include (_spf.google.com)');
    }
    if (mx.length > 1 && mxString.includes('aspmx.l.google.com')) {
      emailHealth.issues.push('Using legacy Google MX records (consider migrating to single smtp.google.com)');
    }
  } else if (mxString.includes('outlook.com')) {
    emailHealth.provider = 'Microsoft 365 / Outlook';
    if (!spfString.includes('spf.protection.outlook.com')) {
      emailHealth.issues.push('Missing Outlook SPF include (spf.protection.outlook.com)');
    }
  } else if (mxString.includes('secureserver.net')) {
    emailHealth.provider = 'GoDaddy Legacy Email';
    if (!spfString.includes('secureserver.net')) {
      emailHealth.issues.push('Missing GoDaddy SPF include (secureserver.net)');
    }
  } else if (mxString.includes('zoho.com')) {
    emailHealth.provider = 'Zoho Mail';
    if (!spfString.includes('zoho.com')) {
      emailHealth.issues.push('Missing Zoho SPF include (zoho.com)');
    }
  } else if (mxString.includes('protonmail.ch')) {
    emailHealth.provider = 'ProtonMail';
    if (!spfString.includes('protonmail.ch')) {
      emailHealth.issues.push('Missing ProtonMail SPF include (protonmail.ch)');
    }
  } else {
    emailHealth.provider = 'Custom/Other';
  }

  if (!spf) {
    emailHealth.issues.push('No SPF record found. Domain is vulnerable to spoofing.');
  } else if (hasMultipleSpf) {
    emailHealth.issues.push('Multiple SPF records found (violates RFC 7208). Email may be rejected.');
  }

  if (!dmarc) {
    emailHealth.issues.push('No DMARC record found. Email security is incomplete.');
  }

  emailHealth.status = emailHealth.issues.length === 0 ? 'optimal' : 'error';
  return emailHealth;
}

export async function auditEmailDomain(domain: string) {
  const [mxRecords, txtRecords] = await Promise.allSettled([
    dns.resolveMx(domain),
    dns.resolveTxt(domain),
  ]);

  const mx = mxRecords.status === 'fulfilled' ? mxRecords.value.sort((a, b) => a.priority - b.priority) : [];
  const txts = txtRecords.status === 'fulfilled' ? txtRecords.value.flat() : [];
  const spfRecords = txts.filter((t) => t.toLowerCase().startsWith('v=spf1'));
  const spf = spfRecords[0] || null;

  let dmarc: string | null = null;
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
    dmarc = dmarcRecords.flat().find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null;
  } catch {
    // no DMARC
  }

  const health = detectEmailProvider(mx, spf, dmarc, spfRecords.length > 1);
  return {
    ...health,
    domain,
    mx,
    spf,
    dmarc,
    txt: txts,
  };
}

export async function testSmtp(req: Request, res: Response) {
  const { host, port, secure, user, pass } = req.body;
  try {
    const transporter = nodemailer.createTransport({
      host,
      port: Number(port),
      secure: Boolean(secure),
      auth: user ? { user, pass } : undefined,
      connectionTimeout: 5000,
      greetingTimeout: 5000,
    });
    await transporter.verify();
    res.json({ success: true, message: 'SMTP connection successful! Authentication verified.' });
  } catch (error: any) {
    res.status(400).json({ success: false, error: error.message });
  }
}

export async function testMx(req: Request, res: Response) {
  const { domain } = req.body;
  try {
    const mxRecords = await dns.resolveMx(domain);
    if (!mxRecords?.length) {
      return res.status(400).json({ success: false, error: 'No MX records found for domain.' });
    }

    const primaryMx = mxRecords.sort((a, b) => a.priority - b.priority)[0].exchange;
    const client = new net.Socket();
    let banner = '';

    await new Promise((resolve, reject) => {
      client.setTimeout(5000);
      client.connect(25, primaryMx, () => {});
      client.on('data', (data) => {
        banner += data.toString();
        client.destroy();
        resolve(true);
      });
      client.on('error', (err) => {
        client.destroy();
        reject(err);
      });
      client.on('timeout', () => {
        client.destroy();
        reject(new Error('Connection timed out waiting for SMTP banner'));
      });
    });

    res.json({ success: true, mx: primaryMx, banner: banner.trim() });
  } catch (error: any) {
    res.status(400).json({ success: false, error: error.message });
  }
}

export async function emailAuditHandler(req: Request, res: Response) {
  const { domain } = req.body;
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }
  try {
    const data = await auditEmailDomain(domain);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(400).json({ success: false, error: error.message });
  }
}
