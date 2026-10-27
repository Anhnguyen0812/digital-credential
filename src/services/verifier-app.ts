import * as http from 'node:http';
import * as path from 'node:path';
import {randomBytes, randomUUID} from 'node:crypto';
import {EventEmitter} from 'node:events';
import {performance} from 'node:perf_hooks';
import * as vc from '@digitalbazaar/vc';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as rdfcCryptosuite} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {createVerifyCryptosuite as createSdVerifySuite} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import QRCode from 'qrcode';
import {createCustomDocumentLoader, createLoaderRegistry} from '../context/document-loader.js';
import {checkHolderIdentity} from '../crypto/holder-binding.js';
import {verifyLegacyProvenanceSignature} from '../crypto/provenance-signer.js';
import {RedisReplayGuard} from '../infra/redis-replay-guard.js';
import {VerifierStatusCache, StatusCacheMode} from '../status/status-store.js';
import {readBody, send, preflight, serveStatic} from './http-util.js';
import {signReceipt} from './receipt-token.js';
import {didWebFromUrl} from './issuer-app.js';
import {createDocStore, DocStore} from '../infra/doc-store.js';
import {createVerifierPortal} from '../portal/verifier-portal.js';

export interface VerifierOptions {
  port?: number;
  publicUrl?: string;
  issuerPublicUrl?: string;      // dung de suy ra did:web cua truong (trust anchor)
  issuerInternalUrl?: string;    // URL noi bo de tai DID Document + Status List
  redis?: RedisReplayGuard;
  docs?: DocStore;
  sessionTtlSeconds?: number;
  statusMode?: StatusCacheMode;
  statusTtlSeconds?: number;
  verifierName?: string;
}

const BASE_MANDATORY: Record<string, string[]> = {
  DegreeCredential: ['studentName', 'graduated'],
  CourseCertificateCredential: ['studentName', 'courseName', 'certificateValid']
};

export type AttackType = 'REPLAY' | 'TAMPER' | 'HOLDER_SPOOF' | 'REVOKED' | 'EXPIRED' | 'SESSION' | 'UNTRUSTED_ISSUER' | 'INCOMPLETE';

export async function createVerifierApp(opts: VerifierOptions = {}) {
  const port = opts.port ?? 4002;
  const publicUrl = opts.publicUrl ?? `http://localhost:${port}`;
  const issuerPublicUrl = opts.issuerPublicUrl ?? 'http://localhost:4001';
  const issuerInternalUrl = opts.issuerInternalUrl ?? issuerPublicUrl;
  const issuerDid = didWebFromUrl(issuerPublicUrl);
  const sessionTtl = opts.sessionTtlSeconds ?? 300;
  const verifierName = opts.verifierName ?? 'Công ty Tuyển dụng Demo (verifier-service)';
  const clientId = `redirect_uri:${publicUrl}/api/verifier/direct-post`;

  const documentLoader = createCustomDocumentLoader(createLoaderRegistry(), {
    remoteDidDocuments: {[issuerDid]: `${issuerInternalUrl}/.well-known/did.json`}
  });

  const guard = opts.redis ?? RedisReplayGuard.fromEnv(sessionTtl);
  await guard.connect();

  const statusCache = new VerifierStatusCache(async (ifNoneMatch) => {
    const r = await fetch(`${issuerInternalUrl}/status/degree-list-1`, {headers: ifNoneMatch ? {'If-None-Match': ifNoneMatch} : {}});
    return {status: r.status, etag: r.headers.get('etag') ?? undefined, body: r.status === 200 ? await r.json() : undefined};
  }, documentLoader, {mode: opts.statusMode ?? 'ETAG_REVALIDATE', ttlMs: (opts.statusTtlSeconds ?? 300) * 1000});

  const docs = opts.docs ?? await createDocStore({postgresUrl: process.env.POSTGRES_URL, table: 'verifier_documents'});
  const portal = await createVerifierPortal({docs, statusCache});

  const sessions = new Map<string, any>();
  let latestState: string | null = null;
  const broker = new EventEmitter();
  broker.setMaxListeners(0);

  function emit(state: string, event: string, data: any) {
    const s = sessions.get(state);
    if(s) s.events.push({event, data});
    broker.emit('evt:' + state, {event, data});
  }

  function fail(state: string, status: number, attackType: AttackType, step: string, reason: string, timings: Record<string, number>, res: http.ServerResponse) {
    const body = {verified: false, step, reason, attackType, httpStatus: status, timings};
    emit(state, 'ATTACK_DETECTED', {verified: false, attackType, httpStatus: status, step, message: reason, timings});
    const s = sessions.get(state);
    if (s) {
      portal.recordVerification({
        state: `${state}-${Date.now()}`,
        at: new Date().toISOString(),
        orgId: s.orgId || 'demo',
        verifierName: s.verifierName || verifierName,
        requestedBy: s.requestedBy || 'demo',
        credentialType: s.type || 'DegreeCredential',
        requestedClaims: s.wanted || [],
        verified: false,
        timings,
        attackType,
        step,
        reason,
        httpStatus: status
      }).catch(() => {});
    }
    return send(res, status, body);
  }

  const server = http.createServer(async (req, res) => {
    if(preflight(req, res)) return;
    const url = new URL(req.url || '/', publicUrl);
    try {
      if(req.method === 'GET' && url.pathname === '/health') return send(res, 200, {ok: true, service: 'verifier', status: statusCache.getMode()});

      // ---- Tao yeu cau OpenID4VP + DCQL + QR ----
      if(req.method === 'POST' && url.pathname === '/api/verifier/request') {
        const body = await readBody(req);
        const type = body.credentialType === 'CourseCertificateCredential' ? 'CourseCertificateCredential' : 'DegreeCredential';
        const wanted: string[] = Array.isArray(body.claims) ? body.claims : [];
        const state = randomUUID();
        const nonce = randomBytes(16).toString('base64url');
        const claimNames = [...new Set([...BASE_MANDATORY[type], ...wanted])];
        const dcql_query = {
          credentials: [{
            id: 'cred',
            format: 'ldp_vc',
            meta: {type_values: [['VerifiableCredential', type]]},
            claims: claimNames.map(c => ({id: c, path: ['credentialSubject', c]}))
          }]
        };
        const rpSession = portal.sessions.get(req);
        const sessionVerifierName = typeof body.verifierName === 'string' && body.verifierName.trim()
          ? body.verifierName.trim()
          : (rpSession ? `${rpSession.user.orgName} (${rpSession.user.email})` : verifierName);
        const request = {
          response_type: 'vp_token', response_mode: 'direct_post', client_id: clientId,
          verifier_name: sessionVerifierName,
          response_uri: `${publicUrl}/api/verifier/direct-post`, nonce, state, dcql_query
        };
        sessions.set(state, {
          request, type, wanted,
          verifierName: sessionVerifierName,
          orgId: rpSession?.user.orgId || 'fpt',
          requestedBy: rpSession?.user.username || 'demo',
          expiresAt: Date.now() + sessionTtl * 1000, events: [], done: false
        });
        latestState = state;
        const baseForQr = typeof body.publicOrigin === 'string' && body.publicOrigin.startsWith('http')
          ? body.publicOrigin.replace(/\/+$/, '')
          : publicUrl;
        const request_uri = `${baseForQr}/api/verifier/request/${state}`;
        const qrPayload = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(request_uri)}`;
        const qrDataUrl = await QRCode.toDataURL(qrPayload, {margin: 1, width: 280});
        return send(res, 201, {request, request_uri, qrPayload, qrDataUrl});
      }

      if(req.method === 'GET' && url.pathname === '/api/verifier/latest') {
        const s = latestState ? sessions.get(latestState) : null;
        if(!s) return send(res, 404, {error: 'chua co phien nao'});
        return send(res, 200, {state: latestState, request: s.request, request_uri: `${publicUrl}/api/verifier/request/${latestState}`});
      }

      let m = /^\/api\/verifier\/request\/([\w-]+)$/.exec(url.pathname);
      if(req.method === 'GET' && m) {
        const s = sessions.get(m[1]);
        return s ? send(res, 200, s.request) : send(res, 404, {error: 'state khong ton tai'});
      }

      // ---- SSE ----
      if(req.method === 'GET' && url.pathname === '/api/verifier/events') {
        const state = url.searchParams.get('state') || '';
        res.writeHead(200, {
          'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive',
          'Access-Control-Allow-Origin': '*', 'X-Accel-Buffering': 'no'
        });
        res.write(': connected\n\n');
        const write = (e: {event: string; data: any}) => res.write(`event: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`);
        for(const e of sessions.get(state)?.events ?? []) write(e);
        const listener = (e: any) => write(e);
        broker.on('evt:' + state, listener);
        const ka = setInterval(() => res.write(': ping\n\n'), 15000);
        req.on('close', () => { clearInterval(ka); broker.off('evt:' + state, listener); });
        return;
      }

      // ---- Cau hinh cache trang thai (danh doi rieng tu vs do tuoi) ----
      if(req.method === 'POST' && url.pathname === '/api/verifier/config') {
        const body = await readBody(req);
        if(body.mode === 'TTL_ONLY' || body.mode === 'ETAG_REVALIDATE') statusCache.setMode(body.mode);
        if(typeof body.ttlSeconds === 'number') statusCache.setTtl(body.ttlSeconds * 1000);
        if(body.invalidate) statusCache.invalidate();
        return send(res, 200, {mode: statusCache.getMode(), counters: statusCache.counters});
      }
      if(req.method === 'GET' && url.pathname === '/api/verifier/metrics') {
        return send(res, 200, {status: {mode: statusCache.getMode(), ...statusCache.counters}, sessions: sessions.size});
      }

      // ---- Xem ban scan so goc (proxy qua Verifier voi Receipt Token) ----
      m = /^\/api\/verifier\/legacy-scan\/([\w-]+)$/.exec(url.pathname);
      if(req.method === 'GET' && m) {
        const s = sessions.get(m[1]);
        if(!s?.receipt || !s.legacyDigest) return send(res, 403, {error: 'chua co bien lai xac minh hop le cho phien nay'});
        const r = await fetch(`${issuerInternalUrl}/api/legacy/document/${encodeURIComponent(s.legacyDigest)}`, {headers: {Authorization: `Bearer ${s.receipt}`}});
        const svg = await r.text();
        res.writeHead(r.status, {'Content-Type': r.headers.get('content-type') || 'text/plain', 'Access-Control-Allow-Origin': '*'});
        return res.end(svg);
      }

      // ---- direct_post: xac minh tuan tu ----
      if(req.method === 'POST' && url.pathname === '/api/verifier/direct-post') {
        const body = await readBody(req);
        const timings: Record<string, number> = {};
        const state = body.state;
        const session = sessions.get(state);
        if(!session) return send(res, 400, {verified: false, step: 'session', reason: 'state khong ton tai', attackType: 'SESSION'});
        if(Date.now() > session.expiresAt) return fail(state, 400, 'SESSION', 'session', 'phien da het han', timings, res);

        const vpEntry = body.vp_token?.[session.request.dcql_query.credentials[0].id];
        const vp = Array.isArray(vpEntry) ? vpEntry[0] : vpEntry;
        if(!vp) return fail(state, 400, 'TAMPER', 'session', 'vp_token thieu', timings, res);
        const {nonce, client_id} = session.request;

        // BUOC 1: Anti-Replay (Redis SET NX EX)
        let t = performance.now();
        const first = await guard.consume(nonce, client_id);
        timings.redisMs = performance.now() - t;
        if(!first) return fail(state, 409, 'REPLAY', 'replay', 'nonce da duoc su dung (Redis SET NX EX)', timings, res);

        // BUOC 2a: rang buoc dinh danh vp.holder === credentialSubject.id
        const identity = checkHolderIdentity(vp);
        if(!identity.verified) return fail(state, 401, 'HOLDER_SPOOF', 'holder_binding', identity.reason!, timings, res);
        const credential = identity.derivedVc;

        if(credential.issuer !== issuerDid && credential.issuer?.id !== issuerDid) {
          return fail(state, 400, 'UNTRUSTED_ISSUER', 'issuer_proof', 'issuer khong nam trong danh sach tin cay', timings, res);
        }
        if(credential.validUntil && Date.parse(credential.validUntil) < Date.now()) {
          return fail(state, 400, 'EXPIRED', 'issuer_proof', `chung chi da het han (validUntil=${credential.validUntil})`, timings, res);
        }

        // BUOC 2b + 3: chu ky VP (Holder, ecdsa-rdfc-2019) va chu ky VC (Issuer, ecdsa-sd-2023)
        t = performance.now();
        let result: any;
        try {
          result = await vc.verify({
            presentation: vp, challenge: nonce, domain: client_id,
            suite: [new DataIntegrityProof({cryptosuite: rdfcCryptosuite}), new DataIntegrityProof({cryptosuite: createSdVerifySuite()})],
            documentLoader, checkStatus: async () => ({verified: true})
          });
        } catch(e: any) { result = {verified: false, error: e?.message}; }
        timings.cryptoMs = performance.now() - t;
        const vcOk = result.credentialResults?.every((c: any) => c.verified) ?? false;
        if(!vcOk) return fail(state, 400, 'TAMPER', 'issuer_proof', 'chu ky ecdsa-sd-2023 cua truong khong hop le (noi dung bi sua)', timings, res);
        if(!result.presentationResult?.verified) {
          return fail(state, 401, 'HOLDER_SPOOF', 'holder_binding', 'chu ky Holder Binding (VP) / challenge / domain khong hop le', timings, res);
        }

        // BUOC 3b: du lieu yeu cau + nguon goc so goc (neu la bang cap lai)
        const subject = credential.credentialSubject;
        const required = [...new Set([...BASE_MANDATORY[session.type], ...session.wanted])];
        const missing = required.filter(c => subject[c] === undefined);
        if(missing.length) return fail(state, 400, 'INCOMPLETE', 'issuer_proof', `thieu claim theo dcql_query: ${missing.join(', ')}`, timings, res);
        let legacyDigest: string | undefined;
        if(subject.legacyProvenance) {
          const prov = subject.legacyProvenance;
          try {
            const vmDoc = (await documentLoader(prov.approverDid)).document;
            const approverKey = await EcdsaMultikey.from(vmDoc);
            if(!(await verifyLegacyProvenanceSignature(prov, approverKey))) throw new Error('bad approver signature');
            legacyDigest = prov.sourceDocumentDigest;
          } catch {
            return fail(state, 400, 'TAMPER', 'issuer_proof', 'chu ky phe duyet so goc (approverSignature) khong hop le', timings, res);
          }
        }

        // BUOC 4: Bitstring Status List (ETag / TTL cache)
        t = performance.now();
        const status = await statusCache.check(credential);
        timings.statusMs = performance.now() - t;
        if(!status.verified) return fail(state, 400, 'REVOKED', 'status', status.reason!, timings, res);

        const activeVerifierName = session.verifierName || verifierName;
        const receipt = signReceipt({aud: activeVerifierName, digest: legacyDigest, exp: Math.floor(Date.now() / 1000) + 600});
        session.receipt = receipt;
        session.legacyDigest = legacyDigest;
        const legacyDocUrl = legacyDigest ? `${publicUrl}/api/verifier/legacy-scan/${state}` : undefined;
        await portal.recordVerification({
          state,
          at: new Date().toISOString(),
          orgId: session.orgId || 'fpt',
          verifierName: activeVerifierName,
          requestedBy: session.requestedBy || 'demo',
          credentialType: session.type,
          requestedClaims: session.wanted,
          verified: true,
          studentName: subject?.studentName,
          disclosedClaims: subject,
          timings,
          httpStatus: 200,
          legacyDocument: legacyDocUrl
        }).catch(() => {});
        const payload = {verified: true, verifierName: activeVerifierName, disclosed: subject, timings, legacyDocument: legacyDocUrl, receiptIssued: true};
        emit(state, 'VERIFICATION_COMPLETED', {verified: true, verifierName: activeVerifierName, disclosedClaims: subject, latency: timings, legacyDocument: payload.legacyDocument});
        return send(res, 200, payload);
      }

      if(await portal.router.handle(req, res, url)) return;

      const publicDir = path.resolve(process.cwd(), 'public');
      if(req.method === 'GET' && serveStatic(res, publicDir, url.pathname, 'verifier.html')) return;
      return send(res, 404, {error: 'not found'});
    } catch(err: any) {
      return send(res, 500, {error: err?.message || String(err)});
    }
  });

  await new Promise<void>(r => server.listen(port, '0.0.0.0', r));
  return {
    server, baseUrl: publicUrl, clientId, issuerDid, statusCache, guard, documentLoader, docs,
    close: async () => { guard.close(); server.closeAllConnections?.(); await new Promise<void>(r => server.close(() => r())); await docs.close(); }
  };
}
