import Database from 'better-sqlite3';

export const db = new Database('dns_sentinel.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    score INTEGER,
    results TEXT
  )
`);

export function getHistory(domain: string) {
  const history = db.prepare('SELECT * FROM audits WHERE domain = ? ORDER BY timestamp DESC LIMIT 10').all(domain);
  return history.map((h: any) => ({ ...h, results: JSON.parse(h.results) }));
}

export function getProfiles() {
  return db.prepare('SELECT DISTINCT domain FROM audits ORDER BY domain ASC').all();
}

export function saveAudit(domain: string, score: number, results: unknown) {
  db.prepare('INSERT INTO audits (domain, score, results) VALUES (?, ?, ?)').run(
    domain,
    score,
    JSON.stringify(results),
  );
}
