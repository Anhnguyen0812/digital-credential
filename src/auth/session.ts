import * as http from 'node:http';
import {createHmac, randomBytes, timingSafeEqual} from 'node:crypto';

// Phien dang nhap phia may chu: session id ngau nhien 256 bit, cookie HttpOnly + SameSite=Lax (+ Secure khi chay HTTPS).
// Moi mien (Nha truong / Vi / Tuyen dung) dung ten cookie rieng nen khong lan phien khi chay chung 1 gateway.
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
    if(k) out[k] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export const isHttps = (req: http.IncomingMessage) =>
  String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https' || !!(req.socket as any).encrypted;

export class SessionManager<U> {
  private sessions = new Map<string, Session<U>>();
  constructor(readonly cookieName: string, private readonly idleMs = 30 * 60 * 1000, private readonly absoluteMs = 8 * 3600 * 1000) {}

  create(user: U, req: http.IncomingMessage, res: http.ServerResponse): Session<U> {
    const id = randomBytes(32).toString('base64url');
    const now = Date.now();
    const s = {id, user, createdAt: now, lastSeen: now};
    this.sessions.set(id, s);
    this.setCookie(req, res, id, Math.floor(this.absoluteMs / 1000));
    return s;
  }

  get(req: http.IncomingMessage): Session<U> | null {
    const id = parseCookies(req)[this.cookieName];
    if(!id) return null;
    const s = this.sessions.get(id);
    if(!s) return null;
    const now = Date.now();
    if(now - s.lastSeen > this.idleMs || now - s.createdAt > this.absoluteMs) { this.sessions.delete(id); return null; }
    s.lastSeen = now;
    return s;
  }

  update(s: Session<U>, user: U) { s.user = user; }

  destroy(req: http.IncomingMessage, res: http.ServerResponse) {
    const id = parseCookies(req)[this.cookieName];
    if(id) this.sessions.delete(id);
    this.setCookie(req, res, '', 0);
  }

  // Huy moi phien cua 1 nguoi dung (vd khi tai khoan bi khoa)
  destroyWhere(pred: (u: U) => boolean) {
    for(const [id, s] of this.sessions) if(pred(s.user)) this.sessions.delete(id);
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
const tokenSecret = () => process.env.SESSION_SECRET || process.env.RECEIPT_SECRET || 'dev-session-secret-change-me';

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
