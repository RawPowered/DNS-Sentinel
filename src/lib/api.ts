export type ChatMessage = { role: 'user' | 'model'; text: string };

export async function fetchProfiles() {
  const res = await fetch('/api/profiles');
  return res.json();
}

export async function fetchHistory(domain: string) {
  const res = await fetch(`/api/history/${domain}`);
  return res.json();
}

export async function analyzeDomain(domain: string, deepViteScan: boolean) {
  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, deepViteScan }),
  });
  if (!res.ok) throw new Error('Analysis failed. Please check the domain and try again.');
  return res.json();
}

export async function aiFixGuide(audit: unknown) {
  const res = await fetch('/api/ai/fix-guide', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ audit }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'AI fix guide failed');
  return data.text as string;
}

export async function aiSecurityChat(audit: unknown, message: string, history: ChatMessage[]) {
  const res = await fetch('/api/ai/security-chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ audit, message, history }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'AI chat failed');
  return data.text as string;
}

export async function aiMxChat(
  message: string,
  context: { smtpResult?: unknown; mxResult?: unknown; emailAuditResult?: unknown },
  history: ChatMessage[],
) {
  const res = await fetch('/api/ai/mx-chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, history, ...context }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'AI email chat failed');
  return data.text as string;
}

export async function testSmtp(body: Record<string, unknown>) {
  const res = await fetch('/api/email/test-smtp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

export async function testMx(domain: string) {
  const res = await fetch('/api/email/test-mx', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  });
  return res.json();
}

export async function emailAudit(domain: string) {
  const res = await fetch('/api/email/audit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  });
  return res.json();
}
