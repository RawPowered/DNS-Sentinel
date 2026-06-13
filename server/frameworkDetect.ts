import https from 'node:https';

export const FETCH_OPTIONS = {
  headers: {
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 DNS-Sentinel/1.0',
  },
};

const BASE_EXPOSURES = [
  '.env',
  '.git/config',
  'wp-config.php.bak',
  'phpinfo.php',
  'server-status',
  'manifest.json',
  '.DS_Store',
  'assets/',
  'robots.txt',
  'package.json',
  'yarn.lock',
  'composer.json',
  'vite.config.js',
  'vite.config.ts',
  'src/main.ts',
];

const DEEP_VITE_PATHS = [
  'dist/index.html',
  'dist/assets/',
  'assets/index.js',
  'assets/index.css',
  '/_vite/manifest.json',
  '.vite/manifest.json',
];

function probePath(domain: string, path: string): Promise<{ path: string; exposed: boolean; status?: number }> {
  return new Promise((resolve) => {
    const reqExp = https.get(`https://${domain}/${path}`, FETCH_OPTIONS, (resExp) => {
      if (path.endsWith('/')) {
        let data = '';
        resExp.on('data', (chunk) => (data += chunk));
        resExp.on('end', () => {
          const isIndexed = resExp.statusCode === 200 && data.toLowerCase().includes('index of');
          resolve({ path, exposed: isIndexed });
        });
      } else if (resExp.statusCode === 200) {
        resolve({ path, exposed: true, status: resExp.statusCode });
        resExp.destroy();
      } else {
        resolve({ path, exposed: false });
        resExp.destroy();
      }
    });
    reqExp.on('error', () => resolve({ path, exposed: false }));
    reqExp.setTimeout(3000, () => {
      reqExp.destroy();
      resolve({ path, exposed: false });
    });
  });
}

export async function scanExposures(domain: string, deepViteScan: boolean) {
  const paths = deepViteScan ? [...BASE_EXPOSURES, ...DEEP_VITE_PATHS] : BASE_EXPOSURES;
  const results = await Promise.all(paths.map((p) => probePath(domain, p)));
  return results.filter((r) => r.exposed).map((r) => r.path);
}

export async function detectWordPress(domain: string) {
  return new Promise<{ detected: boolean; statusCode?: number }>((resolve) => {
    const reqWp = https.get(`https://${domain}/wp-login.php`, FETCH_OPTIONS, (resWp) => {
      const isWp =
        resWp.statusCode === 200 ||
        resWp.headers['x-powered-by']?.toString().toLowerCase().includes('php');
      resolve({ detected: Boolean(isWp), statusCode: resWp.statusCode });
      resWp.destroy();
    });
    reqWp.on('error', () => resolve({ detected: false }));
    reqWp.setTimeout(5000, () => {
      reqWp.destroy();
      resolve({ detected: false });
    });
  });
}

export async function detectVite(domain: string) {
  return new Promise<{ detected: boolean; htmlHints?: string[] }>((resolve) => {
    const reqVite = https.get(`https://${domain}/index.html`, FETCH_OPTIONS, (resVite) => {
      let data = '';
      resVite.on('data', (chunk) => (data += chunk));
      resVite.on('end', () => {
        const hints: string[] = [];
        if (data.includes('vite')) hints.push('vite');
        if (data.includes('/@vite/client')) hints.push('vite-dev-client');
        if (data.includes('assets/index-')) hints.push('hashed-assets');
        if (data.includes('type="module"')) hints.push('es-modules');
        resolve({ detected: hints.length > 0, htmlHints: hints });
      });
    });
    reqVite.on('error', () => resolve({ detected: false }));
    reqVite.setTimeout(5000, () => {
      reqVite.destroy();
      resolve({ detected: false });
    });
  });
}

export async function runDeepViteScan(domain: string) {
  const paths = DEEP_VITE_PATHS;
  const probes = await Promise.all(paths.map((p) => probePath(domain, p)));
  const findings = probes.filter((p) => p.exposed);
  return {
    enabled: true,
    paths: probes,
    findings: findings.map((f) => ({
      path: f.path,
      message:
        f.path.endsWith('/') ? 'Directory listing or open folder exposed' : 'Build artifact or config exposed',
    })),
  };
}

export async function runSslAndHeadersCheck(domain: string) {
  return new Promise<{ ssl: any; headers: Record<string, boolean>; server: string | null }>((resolve) => {
    const reqSsl = https.get(`https://${domain}`, FETCH_OPTIONS, (resSsl) => {
      const cert = (resSsl.socket as any).getPeerCertificate();
      const headers = resSsl.headers;

      const sslInfo =
        cert && Object.keys(cert).length > 0
          ? {
              valid: true,
              issuer: cert.issuer.O,
              validTo: cert.valid_to,
              protocol: (resSsl.socket as any).getProtocol(),
            }
          : { valid: false, error: 'No certificate found' };

      resolve({
        ssl: sslInfo,
        headers: {
          hsts: !!headers['strict-transport-security'],
          csp: !!headers['content-security-policy'],
          xfo: !!headers['x-frame-options'],
          xss: !!headers['x-xss-protection'],
          nosniff: !!headers['x-content-type-options'],
          permissions: !!headers['permissions-policy'],
          referrer: !!headers['referrer-policy'],
        },
        server: (headers['server'] as string) || null,
      });
      resSsl.destroy();
    });

    reqSsl.on('error', (err) => {
      resolve({ ssl: { valid: false, error: err.message }, headers: {}, server: null });
    });
    reqSsl.setTimeout(5000, () => {
      reqSsl.destroy();
      resolve({ ssl: { valid: false, error: 'Timeout' }, headers: {}, server: null });
    });
  });
}
