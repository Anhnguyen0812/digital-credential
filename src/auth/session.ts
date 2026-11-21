import * as http from 'node:http';
import * as net from 'node:net';
import {createHmac, randomBytes, timingSafeEqual} from 'node:crypto';

// Phien dang nhap phia may chu: session id ngau nhien 256 bit, cookie HttpOnly + SameSite=Lax (+ Secure khi chay HTTPS).
// Moi mien (Nha truong / Vi / Tuyen dung) dung ten cookie rieng nen khong lan phien khi chay chung 1 gateway.
// W9-03: Ho tro dong bo phien dang nhap len Redis 7 (RedisSessionStore) voi co che Write-Through + TTL tu dong.
export interface Session<U> {
  id: string;
  user: U;
  createdAt: number;
  lastSeen: number;
}

export function parseCookies(req: http.IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for(const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if(i < 0) continue;
    const k = part.slice(0, i).trim();
    try { if(k) out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* malformed cookie */ }
  }
  return out;
}

export const isHttps = (req: http.IncomingMessage) =>
  String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https' || !!(req.socket as any).encrypted;

/**
 * RedisSessionStore (W9-03): Lưu trữ phiên đăng nhập phân tán trên máy chủ Redis qua giao thức RESP.
 * Hỗ trợ: SET key json EX ttl, GET key, DEL key, TTL key.
 */
export class RedisSessionStore {
  constructor(
    private readonly host = process.env.REDIS_HOST || '127.0.0.1',
    private readonly port = Number(process.env.REDIS_PORT) || 6379
  ) {}

  static keyFor(cookieName: string, sessionId: string): string {
    return `session:${cookieName}:${sessionId}`;
  }

  async command(args: string[]): Promise<string | null> {
    return new Promise((resolve, reject) => {
      const payload = '*' + args.length + '\r\n' + args.map(
        value => '$' + Buffer.byteLength(value) + '\r\n' + value + '\r\n').join('');
      const sock = net.createConnection({host: this.host, port: this.port}, () => sock.write(payload));
      let data = Buffer.alloc(0);
      const unavailable = () => {
        sock.destroy();
        reject(Object.assign(new Error('Redis không khả dụng'), {status: 503}));
      };
      const finish = (value: string | null) => {
        sock.destroy();
        resolve(value);
      };
      sock.setTimeout(1500, unavailable);
      sock.on('error', unavailable);
      sock.on('end', unavailable);
      sock.on('data', chunk => {
        data = Buffer.concat([data, chunk]);
        const end = data.indexOf('\r\n');
        if(end < 0) return;
        const header = data.subarray(0, end).toString('utf8');
        if(header.startsWith('-')) return unavailable();
        if(header === '$-1') return finish(null);
        if(!header.startsWith('$')) return finish(header);
        const length = Number(header.slice(1));
        if(data.length >= end + 4 + length) finish(data.subarray(end + 2, end + 2 + length).toString('utf8'));
      });
    });
  }

  async loadAndTouch<U>(cookieName: string, id: string, idleMs: number, absoluteMs: number) {
    const script = [
      "local raw = redis.call('GET', KEYS[1])",
      'if not raw then return false end',
      'local session = cjson.decode(raw)',
      'local now = tonumber(ARGV[1])',
      'local ttl = math.min(tonumber(ARGV[2]), session.createdAt + tonumber(ARGV[3]) - now)',
      "if ttl <= 0 then redis.call('DEL', KEYS[1]); return false end",
      "redis.call('PEXPIRE', KEYS[1], ttl)",
      'return raw'
    ].join('\n');
    const raw = await this.command(['EVAL', script, '1', RedisSessionStore.keyFor(cookieName, id),
      String(Date.now()), String(idleMs), String(absoluteMs)]);
    return raw ? JSON.parse(raw) as Session<U> : null;
  }

  async setSession<U>(cookieName: string, session: Session<U>, ttlSeconds: number): Promise<boolean> {
    const key = RedisSessionStore.keyFor(cookieName, session.id);
    const reply = await this.command(['SET', key, JSON.stringify(session), 'EX', String(ttlSeconds)]);
    return reply === '+OK';
  }

  async getSession<U>(cookieName: string, sessionId: string): Promise<Session<U> | null> {
    const key = RedisSessionStore.keyFor(cookieName, sessionId);
    const raw = await this.command(['GET', key]);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as Session<U>;
    } catch {
      return null;
    }
  }

  async deleteSession(cookieName: string, sessionId: string): Promise<boolean> {
    const key = RedisSessionStore.keyFor(cookieName, sessionId);
    const reply = await this.command(['DEL', key]);
    return reply !== null && reply.startsWith(':') && Number(reply.slice(1)) > 0;
  }

  async getTtl(cookieName: string, sessionId: string): Promise<number> {
    const key = RedisSessionStore.keyFor(cookieName, sessionId);
    const reply = await this.command(['TTL', key]);
    if (!reply || !reply.startsWith(':')) return -2;
    return Number(reply.slice(1));
  }
}

export class SessionManager<U> {
  readonly redisStore = new RedisSessionStore();

  constructor(
    readonly cookieName: string,
    private readonly idleMs = 30 * 60 * 1000,
    private readonly absoluteMs = 8 * 3600 * 1000
  ) {}

  async create(user: U, req: http.IncomingMessage, res: http.ServerResponse): Promise<Session<U>> {
    const id = randomBytes(32).toString('base64url');
    const now = Date.now();
    const session = {id, user, createdAt: now, lastSeen: now};
    await this.redisStore.setSession(this.cookieName, session, Math.ceil(Math.min(this.idleMs, this.absoluteMs) / 1000));
    this.setCookie(req, res, id, Math.floor(this.absoluteMs / 1000));
    return session;
  }

  async getAsync(req: http.IncomingMessage): Promise<Session<U> | null> {
    const id = parseCookies(req)[this.cookieName];
    if(!id || !/^[A-Za-z0-9_-]{43}$/.test(id)) return null;
    return this.redisStore.loadAndTouch<U>(this.cookieName, id, this.idleMs, this.absoluteMs);
  }

  async destroy(req: http.IncomingMessage, res: http.ServerResponse) {
    const id = parseCookies(req)[this.cookieName];
    if(id) await this.redisStore.deleteSession(this.cookieName, id);
    this.setCookie(req, res, '', 0);
  }

  private setCookie(req: http.IncomingMessage, res: http.ServerResponse, value: string, maxAge: number) {
    const parts = [`${this.cookieName}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAge}`];
    if(isHttps(req)) parts.push('Secure');
    const prev = res.getHeader('Set-Cookie');
    const list = Array.isArray(prev) ? prev : prev ? [String(prev)] : [];
    res.setHeader('Set-Cookie', [...list, parts.join('; ')]);
  }
}

// Chong do mat khau: khoa tam thoi sau 5 lan sai trong 10 phut
export class LoginThrottle {
  private fails = new Map<string, {count: number; first: number; lockedUntil: number}>();
  constructor(private readonly max = 5, private readonly windowMs = 10 * 60 * 1000, private readonly lockMs = 60 * 1000) {}

  check(key: string): number {
    const f = this.fails.get(key);
    if(!f) return 0;
    const now = Date.now();
    if(f.lockedUntil > now) return Math.ceil((f.lockedUntil - now) / 1000);
    if(now - f.first > this.windowMs) this.fails.delete(key);
    return 0;
  }
  fail(key: string) {
    const now = Date.now();
    const f = this.fails.get(key) ?? {count: 0, first: now, lockedUntil: 0};
    f.count++;
    if(f.count >= this.max) { f.lockedUntil = now + this.lockMs; f.count = 0; f.first = now; }
    this.fails.set(key, f);
  }
  success(key: string) { this.fails.delete(key); }
}

// Token HMAC ngan han (dang JWT rut gon) - dung khi Vi goi API cua Nha truong thay mat sinh vien
const tokenSecret = () => process.env.SESSION_SECRET || 'dev-session-secret-change-me';

export function signToken(claims: Record<string, unknown>, ttlSeconds: number): string {
  const payload = Buffer.from(JSON.stringify({...claims, exp: Math.floor(Date.now() / 1000) + ttlSeconds})).toString('base64url');
  const mac = createHmac('sha256', tokenSecret()).update(payload).digest('base64url');
  return `${payload}.${mac}`;
}

export function verifyToken<T = any>(token: string | undefined): (T & {exp: number}) | null {
  if(!token) return null;
  const [payload, mac] = token.split('.');
  if(!payload || !mac) return null;
  const expected = createHmac('sha256', tokenSecret()).update(payload).digest();
  const given = Buffer.from(mac, 'base64url');
  if(given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const c = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return c.exp * 1000 > Date.now() ? c : null;
  } catch { return null; }
}

export const clientIp = (req: http.IncomingMessage) =>
  String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
