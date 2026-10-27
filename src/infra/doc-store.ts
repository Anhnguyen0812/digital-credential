import * as fs from 'node:fs';
import * as path from 'node:path';

// Kho tai lieu don gian cho cac cong nghiep vu (portal): users, students, records, verifications...
// 3 backend: PostgreSQL (JSONB, dung trong Docker), file JSON (vi sinh vien - mo phong bo nho thiet bi), RAM (unit test).
export interface DocStore {
  mode: 'postgres' | 'file' | 'memory';
  get<T = any>(collection: string, id: string): Promise<T | undefined>;
  put<T = any>(collection: string, id: string, doc: T): Promise<void>;
  remove(collection: string, id: string): Promise<void>;
  list<T = any>(collection: string): Promise<T[]>;
  count(collection: string): Promise<number>;
  close(): Promise<void>;
}

class MemoryDocStore implements DocStore {
  mode: DocStore['mode'] = 'memory';
  protected data = new Map<string, Map<string, any>>();
  protected col(c: string) {
    let m = this.data.get(c);
    if(!m) { m = new Map(); this.data.set(c, m); }
    return m;
  }
  async get(c: string, id: string) { const v = this.col(c).get(id); return v === undefined ? undefined : structuredClone(v); }
  async put(c: string, id: string, doc: any) { this.col(c).set(id, structuredClone(doc)); this.changed(); }
  async remove(c: string, id: string) { this.col(c).delete(id); this.changed(); }
  async list(c: string) { return [...this.col(c).values()].map(v => structuredClone(v)); }
  async count(c: string) { return this.col(c).size; }
  async close() {}
  protected changed() {}
}

class FileDocStore extends MemoryDocStore {
  mode: DocStore['mode'] = 'file';
  private timer: NodeJS.Timeout | null = null;
  constructor(private readonly file: string) {
    super();
    fs.mkdirSync(path.dirname(file), {recursive: true});
    if(fs.existsSync(file)) {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, Record<string, any>>;
      for(const [c, docs] of Object.entries(raw)) this.data.set(c, new Map(Object.entries(docs)));
    }
  }
  protected changed() {
    if(this.timer) return;
    this.timer = setTimeout(() => { this.timer = null; this.flush(); }, 50);
  }
  private flush() {
    const out: Record<string, Record<string, any>> = {};
    for(const [c, m] of this.data) out[c] = Object.fromEntries(m);
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(out));
    fs.renameSync(tmp, this.file);
  }
  async close() { if(this.timer) { clearTimeout(this.timer); this.timer = null; } this.flush(); }
}

class PgDocStore implements DocStore {
  mode: DocStore['mode'] = 'postgres';
  constructor(private pool: any, private table: string) {}

  static async connect(url: string, table: string) {
    if(!/^[a-z_]+$/.test(table)) throw new Error('ten bang khong hop le');
    const pg = await import('pg');
    const Pool = (pg as any).Pool ?? (pg as any).default.Pool;
    const pool = new Pool({connectionString: url});
    for(let i = 0; i < 30; i++) {
      try { await pool.query('SELECT 1'); break; } catch(e) { if(i === 29) throw e; await new Promise(r => setTimeout(r, 1000)); }
    }
    await pool.query(`CREATE TABLE IF NOT EXISTS ${table} (
      collection TEXT NOT NULL, id TEXT NOT NULL, data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (collection, id))`);
    return new PgDocStore(pool, table);
  }
  async get(c: string, id: string) {
    const r = await this.pool.query(`SELECT data FROM ${this.table} WHERE collection=$1 AND id=$2`, [c, id]);
    return r.rows[0]?.data;
  }
  async put(c: string, id: string, doc: any) {
    await this.pool.query(
      `INSERT INTO ${this.table} (collection,id,data,updated_at) VALUES ($1,$2,$3,now())
       ON CONFLICT (collection,id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()`, [c, id, JSON.stringify(doc)]);
  }
  async remove(c: string, id: string) { await this.pool.query(`DELETE FROM ${this.table} WHERE collection=$1 AND id=$2`, [c, id]); }
  async list(c: string) {
    const r = await this.pool.query(`SELECT data FROM ${this.table} WHERE collection=$1`, [c]);
    return r.rows.map((x: any) => x.data);
  }
  async count(c: string) {
    const r = await this.pool.query(`SELECT count(*)::int AS n FROM ${this.table} WHERE collection=$1`, [c]);
    return r.rows[0].n;
  }
  async close() { await this.pool.end(); }
}

export async function createDocStore(opts: {postgresUrl?: string; table?: string; file?: string} = {}): Promise<DocStore> {
  if(opts.postgresUrl) return PgDocStore.connect(opts.postgresUrl, opts.table ?? 'documents');
  if(opts.file) return new FileDocStore(opts.file);
  return new MemoryDocStore();
}
