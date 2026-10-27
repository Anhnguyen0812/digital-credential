import * as http from 'node:http';
import {readBody, send} from '../services/http-util.js';

export class HttpError extends Error {
  constructor(readonly status: number, message: string, readonly code?: string) { super(message); }
}

export interface RouteCtx {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  url: URL;
  params: Record<string, string>;
  body: any;
}

type Handler = (ctx: RouteCtx) => Promise<any>;

// Bo dinh tuyen toi gian cho cac API portal: '/api/x/:id' -> params.id; ham xu ly tra ve JSON hoac nem HttpError.
export class Router {
  private routes: {method: string; re: RegExp; keys: string[]; handler: Handler}[] = [];

  add(method: string, pattern: string, handler: Handler) {
    const keys: string[] = [];
    const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
    this.routes.push({method, re, keys, handler});
    return this;
  }
  get(p: string, h: Handler) { return this.add('GET', p, h); }
  post(p: string, h: Handler) { return this.add('POST', p, h); }
  put(p: string, h: Handler) { return this.add('PUT', p, h); }

  async handle(req: http.IncomingMessage, res: http.ServerResponse, url: URL): Promise<boolean> {
    for(const r of this.routes) {
      if(r.method !== req.method) continue;
      const m = r.re.exec(url.pathname);
      if(!m) continue;
      const params: Record<string, string> = {};
      r.keys.forEach((k, i) => params[k] = decodeURIComponent(m[i + 1]));
      try {
        const body = req.method === 'GET' ? {} : await readBody(req, 6_000_000);
        const out = await r.handler({req, res, url, params, body});
        if(!res.headersSent) send(res, out?.__status ?? 200, out?.__status ? out.body : (out ?? {ok: true}), {'Cache-Control': 'no-store'});
      } catch(err: any) {
        if(res.headersSent) { res.end(); return true; }
        if(err instanceof HttpError) send(res, err.status, {error: err.message, code: err.code});
        else send(res, 500, {error: err?.message || String(err)});
      }
      return true;
    }
    return false;
  }
}

export const created = (body: any) => ({__status: 201, body});

export function required(body: any, fields: string[]) {
  const missing = fields.filter(f => body?.[f] === undefined || body?.[f] === null || String(body[f]).trim() === '');
  if(missing.length) throw new HttpError(400, `Thiếu thông tin bắt buộc: ${missing.join(', ')}`);
}

export const str = (v: unknown, max = 200) => String(v ?? '').trim().slice(0, max);
