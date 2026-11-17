import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';

export class RequestBodyError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

async function readText(req: http.IncomingMessage, limit: number): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await(const chunk of req.iterator({destroyOnReturn: false})) {
    size += chunk.length;
    if(size > limit) {
      req.resume();
      throw new RequestBodyError(413, 'Nội dung yêu cầu quá lớn');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function parseObject(text: string) {
  try {
    const value = JSON.parse(text);
    if(value && typeof value === 'object' && !Array.isArray(value)) return value;
  } catch { /* reported below */ }
  throw new RequestBodyError(400, 'Nội dung JSON không hợp lệ');
}

export async function readBody(req: http.IncomingMessage, limit = 5_000_000): Promise<any> {
  const text = await readText(req, limit);
  return text ? parseObject(text) : {};
}

export async function readPresentationResponse(req: http.IncomingMessage, allowJson: boolean) {
  const type = req.headers['content-type']?.split(';')[0].trim().toLowerCase();
  if(type === 'application/json' && allowJson) return readBody(req, 256_000);
  if(type !== 'application/x-www-form-urlencoded') throw new RequestBodyError(415, 'Cần application/x-www-form-urlencoded');
  const form = new URLSearchParams(await readText(req, 256_000));
  if(form.getAll('state').length !== 1 || form.getAll('vp_token').length !== 1) {
    throw new RequestBodyError(400, 'Cần đúng một state và một vp_token');
  }
  return {state: form.get('state'), vp_token: parseObject(form.get('vp_token')!)};
}

export const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,If-None-Match,Authorization,X-Issuer-Role',
  'Access-Control-Expose-Headers': 'ETag,X-Document-Digest,X-Digest-Match'
};

export function send(res: http.ServerResponse, status: number, body: any, headers: Record<string, string> = {}) {
  const isText = typeof body === 'string';
  res.writeHead(status, {
    'Content-Type': isText ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    ...CORS_HEADERS,
    ...headers
  });
  res.end(body === undefined ? undefined : isText ? body : JSON.stringify(body));
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css',
  '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.png': 'image/png'
};

const CLEAN_ROUTES: Record<string, string> = {
  '/issuer': 'issuer.html',
  '/wallet': 'wallet.html',
  '/verifier': 'verifier.html',
  '/demo': 'index.html'
};

export function serveStatic(res: http.ServerResponse, publicDir: string, pathname: string, defaultIndex = 'index.html'): boolean {
  const rel = pathname === '/' ? defaultIndex : (CLEAN_ROUTES[pathname] || pathname.slice(1));
  const full = path.join(publicDir, path.normalize(rel));
  if(!full.startsWith(publicDir + path.sep) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) return false;
  res.writeHead(200, {'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', ...CORS_HEADERS});
  fs.createReadStream(full).pipe(res);
  return true;
}

export function preflight(req: http.IncomingMessage, res: http.ServerResponse): boolean {
  if(req.method !== 'OPTIONS') return false;
  res.writeHead(204, CORS_HEADERS);
  res.end();
  return true;
}
