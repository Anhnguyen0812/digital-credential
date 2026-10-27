import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';

export function readBody(req: http.IncomingMessage, limit = 5_000_000): Promise<any> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if(size > limit) { reject(new Error('payload qua lon')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if(!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('JSON khong hop le')); }
    });
    req.on('error', reject);
  });
}

export const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
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
  if(!full.startsWith(publicDir) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) return false;
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
