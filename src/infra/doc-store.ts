import * as fs from 'node:fs';
import * as path from 'node:path';
import {AsyncLocalStorage} from 'node:async_hooks';

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
  atomic<T>(work: () => Promise<T>): Promise<T>;
}

class MemoryDocStore implements DocStore {
  mode: DocStore['mode'] = 'memory';
  protected data = new Map<string, Map<string, any>>();
  private readonly transaction = new AsyncLocalStorage<typeof this.data>();
  private pending: Promise<void> = Promise.resolve();

  async atomic<T>(work: () => Promise<T>): Promise<T> {
    if(this.transaction.getStore()) return work();
    const previous = this.pending;
    let release!: () => void;
    this.pending = new Promise(resolve => { release = resolve; });
    await previous;
    try {
      const staged = structuredClone(this.data);
      const result = await this.transaction.run(staged, work);
      this.data = staged;
      this.changed();
      return result;
    } finally {
      release();
    }
  }

  protected col(c: string) {
    const data = this.transaction.getStore() ?? this.data;
    let m = data.get(c);
    if(!m) { m = new Map(); data.set(c, m); }
    return m;
  }
  async get(c: string, id: string) { const v = this.col(c).get(id); return v === undefined ? undefined : structuredClone(v); }
  async put(c: string, id: string, doc: any) { await this.atomic(async () => { this.col(c).set(id, structuredClone(doc)); }); }
  async remove(c: string, id: string) { await this.atomic(async () => { this.col(c).delete(id); }); }
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
  private readonly transaction = new AsyncLocalStorage<any>();
  constructor(private pool: any, private table: string) {}

  private get db() { return this.transaction.getStore() ?? this.pool; }

  async atomic<T>(work: () => Promise<T>): Promise<T> {
    if(this.transaction.getStore()) return work();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [this.table]);
      const result = await this.transaction.run(client, work);
      await client.query('COMMIT');
      return result;
    } catch(error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  static async connect(url: string, table: string) {
    if(!/^[a-z_]+$/.test(table)) throw new Error('ten bang khong hop le');
    const pg = await import('pg');
    const Pool = (pg as any).Pool ?? (pg as any).default.Pool;
    const pool = new Pool({connectionString: url});
    for(let i = 0; i < 30; i++) {
      try { await pool.query('SELECT 1'); break; } catch(e) { if(i === 29) throw e; await new Promise(r => setTimeout(r, 1000)); }
    }
    const store = new PgDocStore(pool, table);
    try {
      await store.atomic(async () => {
        await store.db.query('CREATE TABLE IF NOT EXISTS ' + table + ' (' +
          'collection TEXT NOT NULL, id TEXT NOT NULL, data JSONB NOT NULL, ' +
          'updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (collection, id))');
        await store.db.query('CREATE UNIQUE INDEX IF NOT EXISTS ' + table + '_record_status_index ON ' + table +
          " ((data->>'statusListIndex')) WHERE collection = 'records' AND data->>'statusListIndex' IS NOT NULL");
      });
      return store;
    } catch(error) {
      await pool.end();
      throw error;
    }
  }

  async get(c: string, id: string) {
    const r = await this.db.query(`SELECT data FROM ${this.table} WHERE collection=$1 AND id=$2`, [c, id]);
    return r.rows[0]?.data;
  }
  async put(c: string, id: string, doc: any) {
    await this.db.query(
      `INSERT INTO ${this.table} (collection,id,data,updated_at) VALUES ($1,$2,$3,now())
       ON CONFLICT (collection,id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()`, [c, id, JSON.stringify(doc)]);
  }
  async remove(c: string, id: string) { await this.db.query(`DELETE FROM ${this.table} WHERE collection=$1 AND id=$2`, [c, id]); }
  async list(c: string) {
    const r = await this.db.query(`SELECT data FROM ${this.table} WHERE collection=$1`, [c]);
    return r.rows.map((x: any) => x.data);
  }
  async count(c: string) {
    const r = await this.db.query(`SELECT count(*)::int AS n FROM ${this.table} WHERE collection=$1`, [c]);
    return r.rows[0].n;
  }
  async close() { await this.pool.end(); }
}

export async function createDocStore(opts: {postgresUrl?: string; table?: string; file?: string} = {}): Promise<DocStore> {
  if(opts.postgresUrl) return PgDocStore.connect(opts.postgresUrl, opts.table ?? 'documents');
  if(opts.file) return new FileDocStore(opts.file);
  return new MemoryDocStore();
}
