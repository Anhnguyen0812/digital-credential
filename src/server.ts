import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {randomBytes, randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {makeIssuerSetup} from './issuer-setup.js';
import {
  issueLegacyDegree,
  discloseWithPointers,
  signStatusListCredential,
  verifyStatusListCredential,
  verifyCrypto
} from './credential-service.js';
import {StatusStore} from './status-store.js';
import {makeStatusListCredential} from './bitstring-status.js';
import {RedisReplayGuard} from './redis-replay-guard.js';
import {ISSUER_ID, STATUS_URL, VERIFY_AUDIENCE} from './config.js';
import {sampleInput} from './sample.js';
import type {DegreeInput} from './types.js';

// ============================================================
// Prototype server Tuan 7: Issuer + Wallet + Verifier tren 1 tien trinh
// ============================================================

export type AppOptions = {port?: number; redisPort?: number; sessionTtlSeconds?: number; statusCacheSeconds?: number};

const MANDATORY_CLAIMS = ['studentName', 'graduated', 'legacyProvenance'];
const OPTIONAL_CLAIMS = ['major', 'degreeName', 'graduationDate', 'gpa', 'classification', 'studentCode'];

function readBody(req: http.IncomingMessage, limit = 1_000_000): Promise<any> {
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

function send(res: http.ServerResponse, status: number, body: any, headers: Record<string, string> = {}) {
  const data = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
  res.writeHead(status, {'Content-Type': 'application/json; charset=utf-8', ...headers});
  res.end(data);
}

export async function createApp(opts: AppOptions = {}) {
  const port = opts.port ?? 3000;
  const sessionTtl = opts.sessionTtlSeconds ?? 300;
  const statusCacheMs = (opts.statusCacheSeconds ?? 300) * 1000;
  const baseUrl = `http://localhost:${port}`;

  const setup = await makeIssuerSetup();
  const issuerStore = new StatusStore();          // danh sach trang thai ben truong
  const issued = new Map<string, any>();         // credential da cap (id -> base VC)
  let nextIndex = 1000;

  const guard = new RedisReplayGuard('127.0.0.1', opts.redisPort ?? 6379, sessionTtl);
  await guard.connect();

  // Phien xac minh cua verifier (state -> request)
  const sessions = new Map<string, {nonce: string; audience: string; dcql_query: any; expiresAt: number; result?: any}>();

  // Cache status list phia verifier (dung nhu CDN cache), tranh goi ve truong moi lan
  let statusCache: {store: StatusStore; fetchedAt: number} | null = null;
  const statusCounters = {issuerHits: 0, cacheHits: 0};

  async function issuerStatusListCredential() {
    return signStatusListCredential(makeStatusListCredential(STATUS_URL, ISSUER_ID, issuerStore.list), setup);
  }

  // Verifier tai status list qua HTTP that tu endpoint cua truong, kiem tra chu ky roi moi giai nen
  async function verifierStatusStore(): Promise<StatusStore> {
    if(statusCache && Date.now() - statusCache.fetchedAt < statusCacheMs) {
      statusCounters.cacheHits++;
      return statusCache.store;
    }
    const r = await fetch(`${baseUrl}/status/degree-list-1`);
    const slc = await r.json();
    const sig = await verifyStatusListCredential(slc, setup);
    if(!sig.verified) throw new Error('chu ky Status List Credential khong hop le');
    const store = StatusStore.fromEncodedList(slc.credentialSubject.encodedList);
    statusCache = {store, fetchedAt: Date.now()};
    return store;
  }

  function invalidateStatusCache() { statusCache = null; }

  const publicDir = path.resolve(process.cwd(), 'public');

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', baseUrl);
    try {
      // ---------------- STATIC (giao dien preview) ----------------
      if(req.method === 'GET' && !url.pathname.startsWith('/api') && !url.pathname.startsWith('/status')) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        const full = path.join(publicDir, path.normalize(file));
        if(!full.startsWith(publicDir) || !fs.existsSync(full)) return send(res, 404, {error: 'not found'});
        const ext = path.extname(full);
        const types: Record<string, string> = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.webmanifest': 'application/manifest+json'};
        res.writeHead(200, {'Content-Type': types[ext] || 'application/octet-stream'});
        return fs.createReadStream(full).pipe(res);
      }

      // ---------------- ISSUER ----------------
      if(req.method === 'GET' && url.pathname === '/status/degree-list-1') {
        statusCounters.issuerHits++;
        const slc = await issuerStatusListCredential();
        return send(res, 200, slc, {'Cache-Control': `public, max-age=${statusCacheMs / 1000}`});
      }

      if(req.method === 'POST' && url.pathname === '/api/issuer/issue') {
        const body = await readBody(req);
        const index = nextIndex++;
        const input: DegreeInput = {
          id: 'urn:uuid:' + randomUUID(),
          statusIndex: index,
          subject: {...sampleInput.subject, ...(body.subject || {})}
        };
        const vcBase = await issueLegacyDegree(input, setup);
        issued.set(input.id, vcBase);
        return send(res, 201, {statusListIndex: index, credential: vcBase});
      }

      if(req.method === 'POST' && url.pathname === '/api/issuer/revoke') {
        const body = await readBody(req);
        issuerStore.revoke(Number(body.statusListIndex));
        invalidateStatusCache(); // demo: buoc verifier lay lai danh sach moi
        return send(res, 200, {revoked: Number(body.statusListIndex)});
      }

      // ---------------- VERIFIER: tao yeu cau OpenID4VP + DCQL ----------------
      if(req.method === 'POST' && url.pathname === '/api/verifier/request') {
        const body = await readBody(req);
        const wanted: string[] = Array.isArray(body.claims) && body.claims.length ? body.claims : ['major'];
        const state = randomUUID();
        const nonce = randomBytes(16).toString('base64url');
        const dcql_query = {
          credentials: [{
            id: 'degree',
            format: 'ldp_vc',
            meta: {type_values: [['VerifiableCredential', 'DegreeCredential']]},
            claims: [...MANDATORY_CLAIMS, ...wanted].map(c => ({id: c, path: ['credentialSubject', c]}))
          }]
        };
        sessions.set(state, {nonce, audience: VERIFY_AUDIENCE, dcql_query, expiresAt: Date.now() + sessionTtl * 1000});
        const request = {
          response_type: 'vp_token',
          response_mode: 'direct_post',
          client_id: 'redirect_uri:' + `${baseUrl}/api/verifier/direct-post`,
          response_uri: `${baseUrl}/api/verifier/direct-post`,
          nonce,
          state,
          dcql_query
        };
        return send(res, 201, {request, request_uri_for_qr: `openid4vp://?state=${state}`});
      }

      // ---------------- WALLET: xem truoc + tao presentation ----------------
      if(req.method === 'POST' && url.pathname === '/api/wallet/preview') {
        const body = await readBody(req);
        const claims = body.request?.dcql_query?.credentials?.[0]?.claims || [];
        const requested = claims.map((c: any) => c.path[c.path.length - 1]);
        const subject = body.credential?.credentialSubject || {};
        const allKeys = Object.keys(subject).filter(k => k !== 'id');
        return send(res, 200, {
          verifier: body.request?.client_id,
          mandatory: allKeys.filter(k => MANDATORY_CLAIMS.includes(k)),
          requestedOptional: requested.filter((k: string) => !MANDATORY_CLAIMS.includes(k)),
          hidden: allKeys.filter(k => !requested.includes(k) && !MANDATORY_CLAIMS.includes(k))
        });
      }

      if(req.method === 'POST' && url.pathname === '/api/wallet/present') {
        const body = await readBody(req);
        if(body.consent !== true) return send(res, 400, {error: 'nguoi hoc chua chap thuan chia se'});
        const reqObj = body.request;
        const claims = reqObj.dcql_query.credentials[0].claims;
        const approved: string[] = Array.isArray(body.approvedClaims) ? body.approvedClaims : claims.map((c: any) => c.path[1]);
        const pointers = ['/credentialSubject/id', ...approved.filter(c => !MANDATORY_CLAIMS.includes(c) && OPTIONAL_CLAIMS.includes(c)).map(c => '/credentialSubject/' + c)];
        const t0 = performance.now();
        const derived = await discloseWithPointers(body.credential, setup, pointers);
        const deriveMs = performance.now() - t0;
        const vp_token = {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiablePresentation'],
          holder: derived.credentialSubject.id,
          nonce: reqObj.nonce,
          audience: VERIFY_AUDIENCE,
          verifiableCredential: [derived]
        };
        return send(res, 200, {vp_token: {degree: [vp_token]}, state: reqObj.state, deriveMs});
      }

      // ---------------- VERIFIER: nhan direct_post va xac minh 3 buoc ----------------
      if(req.method === 'POST' && url.pathname === '/api/verifier/direct-post') {
        const body = await readBody(req);
        const timings: Record<string, number> = {};
        const session = sessions.get(body.state);
        if(!session) return send(res, 400, {verified: false, step: 'session', reason: 'state khong ton tai'});
        if(Date.now() > session.expiresAt) return send(res, 400, {verified: false, step: 'session', reason: 'phien da het han'});

        const vp = body.vp_token?.degree?.[0];
        if(!vp || vp.nonce !== session.nonce || vp.audience !== session.audience) {
          return send(res, 400, {verified: false, step: 'binding', reason: 'nonce/audience khong khop phien'});
        }

        // Buoc 1: Redis SET NX EX (nguyen tu)
        let t = performance.now();
        const first = await guard.consume(vp.nonce, vp.audience);
        timings.redisMs = performance.now() - t;
        if(!first) return send(res, 409, {verified: false, step: 'replay', reason: 'nonce da duoc su dung', timings});

        // Buoc 2: kiem tra chu ky ECDSA-SD cua derived credential
        const credential = vp.verifiableCredential?.[0];
        t = performance.now();
        const crypto = await verifyCrypto(credential, setup);
        timings.cryptoMs = performance.now() - t;
        if(!crypto.verified) return send(res, 400, {verified: false, step: 'crypto', reason: 'chu ky khong hop le', timings});

        // Buoc 3: tra cuu Bitstring Status List (tai qua HTTP + cache)
        t = performance.now();
        const store = await verifierStatusStore();
        const status = store.check(credential);
        timings.statusMs = performance.now() - t;
        if(!status.verified) return send(res, 400, {verified: false, step: 'status', reason: status.reason, timings});

        const result = {verified: true, disclosed: credential.credentialSubject, timings};
        session.result = result;
        return send(res, 200, result);
      }

      if(req.method === 'GET' && url.pathname === '/api/metrics') {
        return send(res, 200, {statusCounters, sessions: sessions.size, issued: issued.size});
      }

      return send(res, 404, {error: 'not found'});
    } catch(err: any) {
      return send(res, 500, {error: err?.message || String(err)});
    }
  });

  await new Promise<void>(r => server.listen(port, r));
  return {
    server, guard, baseUrl, statusCounters,
    close: async () => { guard.close(); await new Promise<void>(r => server.close(() => r())); }
  };
}

// Chay truc tiep: npx tsx src/server.ts
if(process.argv[1] && process.argv[1].endsWith('server.ts')) {
  createApp({port: Number(process.env.PORT) || 3000}).then(app => {
    console.log(`Prototype dang chay tai ${app.baseUrl}`);
  });
}
