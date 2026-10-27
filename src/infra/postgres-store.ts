import {randomUUID} from 'node:crypto';

// Luu tru ben vung (PostgreSQL 16): ho so, lich su phe duyet 2 buoc, anh xa statusListIndex, audit log (khong luu PII).
// Neu khong co POSTGRES_URL thi dung bo nho (unit test / chay cuc bo).
export interface IssuanceRecord {
  id: string;
  kind: 'degree' | 'course' | 'legacy_degree';
  status: 'PENDING_REVIEW' | 'APPROVED' | 'ISSUED' | 'REVOKED';
  statusListIndex?: number;
  holderDid: string;
  digest?: string;
  createdAt: string;
}

export interface AuditEntry {
  id: string;
  event: string;
  detail: Record<string, any>;
  at: string;
}

export interface AuditStore {
  mode: 'postgres' | 'memory';
  saveRecord(r: IssuanceRecord): Promise<void>;
  updateRecord(id: string, patch: Partial<IssuanceRecord>): Promise<void>;
  getRecord(id: string): Promise<IssuanceRecord | undefined>;
  listRecords(): Promise<IssuanceRecord[]>;
  audit(event: string, detail?: Record<string, unknown>): Promise<void>;
  auditCount(): Promise<number>;
  listAudit(limit?: number): Promise<AuditEntry[]>;
  close(): Promise<void>;
}

class MemoryStore implements AuditStore {
  mode = 'memory' as const;
  private records = new Map<string, IssuanceRecord>();
  private logs: any[] = [];
  async saveRecord(r: IssuanceRecord) { this.records.set(r.id, r); }
  async updateRecord(id: string, patch: Partial<IssuanceRecord>) {
    const r = this.records.get(id); if(r) this.records.set(id, {...r, ...patch});
  }
  async getRecord(id: string) { return this.records.get(id); }
  async listRecords() { return [...this.records.values()]; }
  async audit(event: string, detail: Record<string, unknown> = {}) { this.logs.push({id: String(this.logs.length + 1), event, detail, at: new Date().toISOString()}); }
  async auditCount() { return this.logs.length; }
  async listAudit(limit = 200) { return this.logs.slice(-limit).reverse(); }
  async close() {}
}

class PgStore implements AuditStore {
  mode = 'postgres' as const;
  constructor(private pool: any) {}

  static async connect(url: string): Promise<PgStore> {
    const pg = await import('pg');
    const Pool = (pg as any).Pool ?? (pg as any).default.Pool;
    const pool = new Pool({connectionString: url});
    for(let i = 0; i < 30; i++) {
      try { await pool.query('SELECT 1'); break; } catch(e) { if(i === 29) throw e; await new Promise(r => setTimeout(r, 1000)); }
    }
    await pool.query(`
      CREATE TABLE IF NOT EXISTS issuance_records (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, status_list_index INT,
        holder_did TEXT NOT NULL, digest TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id BIGSERIAL PRIMARY KEY, event TEXT NOT NULL, detail JSONB NOT NULL DEFAULT '{}', at TIMESTAMPTZ NOT NULL DEFAULT now()
      );`);
    return new PgStore(pool);
  }

  private map(row: any): IssuanceRecord {
    return {
      id: row.id, kind: row.kind, status: row.status, statusListIndex: row.status_list_index ?? undefined,
      holderDid: row.holder_did, digest: row.digest ?? undefined, createdAt: new Date(row.created_at).toISOString()
    };
  }
  async saveRecord(r: IssuanceRecord) {
    await this.pool.query(
      'INSERT INTO issuance_records (id,kind,status,status_list_index,holder_did,digest,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [r.id, r.kind, r.status, r.statusListIndex ?? null, r.holderDid, r.digest ?? null, r.createdAt]);
  }
  async updateRecord(id: string, p: Partial<IssuanceRecord>) {
    await this.pool.query(
      'UPDATE issuance_records SET status=COALESCE($2,status), status_list_index=COALESCE($3,status_list_index), digest=COALESCE($4,digest) WHERE id=$1',
      [id, p.status ?? null, p.statusListIndex ?? null, p.digest ?? null]);
  }
  async getRecord(id: string) {
    const r = await this.pool.query('SELECT * FROM issuance_records WHERE id=$1', [id]);
    return r.rows[0] ? this.map(r.rows[0]) : undefined;
  }
  async listRecords() {
    const r = await this.pool.query('SELECT * FROM issuance_records ORDER BY created_at DESC LIMIT 100');
    return r.rows.map((x: any) => this.map(x));
  }
  async audit(event: string, detail: Record<string, unknown> = {}) {
    await this.pool.query('INSERT INTO audit_log (event, detail) VALUES ($1,$2)', [event, JSON.stringify(detail)]);
  }
  async auditCount() {
    const r = await this.pool.query('SELECT count(*)::int AS n FROM audit_log');
    return r.rows[0].n;
  }
  async listAudit(limit = 200) {
    const r = await this.pool.query('SELECT id, event, detail, at FROM audit_log ORDER BY id DESC LIMIT $1', [limit]);
    return r.rows.map((x: any) => ({id: String(x.id), event: x.event, detail: x.detail, at: new Date(x.at).toISOString()}));
  }
  async close() { await this.pool.end(); }
}

export async function createAuditStore(url = process.env.POSTGRES_URL): Promise<AuditStore> {
  if(!url) return new MemoryStore();
  return PgStore.connect(url);
}

export const newRecordId = () => randomUUID();
