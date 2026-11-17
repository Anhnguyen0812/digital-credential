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
import {HttpError} from '../portal/router.js';
import {PRESENTATION_PROFILES, checkPresentationProfile, type CredentialProfile} from '../profiles/presentation-policy.js';
import {readBody, readPresentationResponse, RequestBodyError, send, preflight, serveStatic} from './http-util.js';
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
  demoMode?: boolean;
}

export type AttackType = 'REPLAY' | 'TAMPER' | 'HOLDER_SPOOF' | 'REVOKED' | 'EXPIRED' | 'SESSION' | 'UNTRUSTED_ISSUER' | 'INCOMPLETE';

export async function createVerifierApp(opts: VerifierOptions = {}) {
  const port = opts.port ?? 4002;
  const publicUrl = opts.publicUrl?.replace(/\/+$/, '') ?? `http://localhost:${port}`;
  const issuerPublicUrl = opts.issuerPublicUrl?.replace(/\/+$/, '') ?? 'http://localhost:4001';
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

  function makeCache(purpose: 'revocation' | 'suspension') {
    const pathname = '/status/degree-list-1' + (purpose === 'suspension' ? '-suspension' : '');
    return new VerifierStatusCache(async etag => {
      const r = await fetch(issuerInternalUrl + pathname, {
        headers: etag ? {'If-None-Match': etag} : {}, redirect: 'error', signal: AbortSignal.timeout(5000)
      });
      return {status: r.status, etag: r.headers.get('etag') ?? undefined, body: r.status === 200 ? await r.json() : undefined};
    }, documentLoader, {mode: opts.statusMode ?? 'ETAG_REVALIDATE', ttlMs: (opts.statusTtlSeconds ?? 300) * 1000},
      {url: issuerPublicUrl + pathname, issuer: issuerDid, purpose});
  }
  const statusCache = makeCache('revocation');
  const suspensionCache = makeCache('suspension');
  const docs = opts.docs ?? await createDocStore({postgresUrl: process.env.POSTGRES_URL, table: 'verifier_documents'});
  const demoMode = opts.demoMode === true && docs.mode === 'memory';
  const portal = await docs.atomic(() => createVerifierPortal({docs, statusCache, suspensionCache}));

  const sessions = new Map<string, any>();
  function liveSession(state: string) {
    const session = sessions.get(state);
    if(session && Date.now() >= session.expiresAt) sessions.delete(state);
    return sessions.get(state);
  }

  async function ownedSession(req: http.IncomingMessage, state: string) {
    const session = liveSession(state);
    if(demoMode && session?.orgId === 'demo') return session;
    const user = await portal.need({req}, 'history.read');
    if(!session || session.orgId !== user.orgId) throw new HttpError(404, 'Không tìm thấy phiên xác minh');
    return session;
  }
  const broker = new EventEmitter();
  broker.setMaxListeners(0);

  function emit(state: string, event: string, data: any) {
    const s = sessions.get(state);
    if(s && s.events.length < 32) s.events.push({event, data});
    broker.emit('evt:' + state, {event, data});
  }

  function fail(state: string, status: number, attackType: AttackType, step: string, reason: string, timings: Record<string, number>, res: http.ServerResponse) {
    const body = {verified: false, step, reason, attackType, httpStatus: status, timings};
    emit(state, 'ATTACK_DETECTED', {verified: false, attackType, httpStatus: status, step, message: reason, timings});
    const s = sessions.get(state);
    if (s && s.events.length < 32 && attackType !== 'REPLAY') {
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
        const user = !demoMode || req.headers.cookie?.includes('rp_sid=')
          ? await portal.need({req}, 'request.create') : undefined;
        const body = await readBody(req, 16_000);
        const type = body.credentialType ?? 'DegreeCredential';
        if(typeof type !== 'string' || !Object.hasOwn(PRESENTATION_PROFILES, type)) throw new HttpError(400, 'Loại văn bằng không được hỗ trợ');
        const profile = PRESENTATION_PROFILES[type as CredentialProfile];
        const wanted: string[] = body.claims ?? [];
        if(!Array.isArray(wanted) || wanted.length > 20 ||
          wanted.some(claim => !profile.optional.includes(claim) && !profile.required.includes(claim))) {
          throw new HttpError(400, 'Yêu cầu thuộc tính ngoài profile');
        }
        for(const state of sessions.keys()) liveSession(state);
        if(sessions.size >= 1000) throw new HttpError(429, 'Đã đạt giới hạn phiên xác minh');
        const state = randomUUID();
        const nonce = randomBytes(16).toString('base64url');
        const claimNames = [...new Set([...profile.required, ...wanted])];
        const dcql_query = {
          credentials: [{
            id: 'cred',
            format: 'ldp_vc',
            meta: {type_values: [['VerifiableCredential', type]]},
            claims: claimNames.map(c => ({id: c, path: ['credentialSubject', c]}))
          }]
        };
        const sessionVerifierName = user ? user.orgName : verifierName;
        const request = {
          response_type: 'vp_token', response_mode: 'direct_post', client_id: clientId,
          verifier_name: sessionVerifierName,
          response_uri: `${publicUrl}/api/verifier/direct-post`, nonce, state, dcql_query
        };
        sessions.set(state, {
          request, type, wanted,
          verifierName: sessionVerifierName,
          orgId: user?.orgId || 'demo',
          requestedBy: user?.username || 'demo',
          expiresAt: Date.now() + sessionTtl * 1000, events: [], done: false
        });
        const request_uri = publicUrl + '/api/verifier/request/' + state;
        const qrPayload = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(request_uri)}`;
        const qrDataUrl = await QRCode.toDataURL(qrPayload, {margin: 1, width: 280});
        return send(res, 201, {request, request_uri, qrPayload, qrDataUrl});
      }

      let m = /^\/api\/verifier\/request\/([\w-]+)$/.exec(url.pathname);
      if(req.method === 'GET' && m) {
        const s = liveSession(m[1]);
        return s && !s.done ? send(res, 200, s.request, {'Cache-Control': 'no-store'}) : send(res, 404, {error: 'state khong ton tai'});
      }

      // ---- SSE ----
      if(req.method === 'GET' && url.pathname === '/api/verifier/events') {
        const state = url.searchParams.get('state') || '';
        const session = await ownedSession(req, state);
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
        const expiry = setTimeout(() => res.end(), Math.max(0, session.expiresAt - Date.now()));
        res.on('close', () => { clearTimeout(expiry); clearInterval(ka); broker.off('evt:' + state, listener); });
        return;
      }

      // ---- Cau hinh cache trang thai (danh doi rieng tu vs do tuoi) ----
      if(req.method === 'POST' && url.pathname === '/api/verifier/config') {
        if(!demoMode) await portal.need({req}, 'config.manage');
        const body = await readBody(req, 4096);
        if(body.ttlSeconds !== undefined && (!Number.isInteger(body.ttlSeconds) || body.ttlSeconds < 1 || body.ttlSeconds > 300)) {
          throw new HttpError(400, 'TTL cần nằm trong khoảng 1 đến 300 giây');
        }
        for(const cache of [statusCache, suspensionCache]) {
          if(body.mode === 'TTL_ONLY' || body.mode === 'ETAG_REVALIDATE') cache.setMode(body.mode);
          if(body.ttlSeconds !== undefined) cache.setTtl(body.ttlSeconds * 1000);
          if(body.invalidate) cache.invalidate();
        }
        return send(res, 200, {mode: statusCache.getMode(), counters: statusCache.counters});
      }
      if(req.method === 'GET' && url.pathname === '/api/verifier/metrics') {
        if(!demoMode) await portal.need({req}, 'config.manage');
        return send(res, 200, {status: {mode: statusCache.getMode(), ...statusCache.counters}, sessions: sessions.size});
      }

      // ---- Xem ban scan so goc (proxy qua Verifier voi Receipt Token) ----
      m = /^\/api\/verifier\/legacy-scan\/([\w-]+)$/.exec(url.pathname);
      if(req.method === 'GET' && m) {
        const s = await ownedSession(req, m[1]);
        if(!s?.receipt || !s.legacyDigest) return send(res, 403, {error: 'chua co bien lai xac minh hop le cho phien nay'});
        const r = await fetch(`${issuerInternalUrl}/api/legacy/document/${encodeURIComponent(s.legacyDigest)}`, {headers: {Authorization: `Bearer ${s.receipt}`}});
        const svg = await r.text();
        res.writeHead(r.status, {'Content-Type': r.headers.get('content-type') || 'text/plain', 'Access-Control-Allow-Origin': '*'});
        return res.end(svg);
      }

      // ---- direct_post: xac minh tuan tu ----
      if(req.method === 'POST' && url.pathname === '/api/verifier/direct-post') {
        const body = await readPresentationResponse(req, demoMode);
        const timings: Record<string, number> = {};
        const state = body.state;
        const session = typeof state === 'string' ? liveSession(state) : undefined;
        if(!session) return send(res, 400, {verified: false, step: 'session', reason: 'state khong ton tai', attackType: 'SESSION'});
        if(session.done) return fail(state, 409, 'REPLAY', 'replay', 'Phiên đã hoàn tất', timings, res);
        if(session.attempts >= 250) throw new HttpError(429, 'Đã đạt giới hạn lượt gửi');
        session.attempts = (session.attempts ?? 0) + 1;

        const token = body.vp_token;
        const entries = token?.[session.request.dcql_query.credentials[0].id];
        const vp = Array.isArray(entries) && entries.length === 1 ? entries[0] : undefined;
        if(!vp || Object.keys(token).length !== 1 || !Array.isArray(vp.verifiableCredential) || vp.verifiableCredential.length !== 1) {
          return fail(state, 400, 'TAMPER', 'session', 'Cần một bản trình bày chứa đúng một văn bằng', timings, res);
        }
        const {nonce, client_id} = session.request;
        let t: number;
        const identity = checkHolderIdentity(vp);
        if(!identity.verified) return fail(state, 401, 'HOLDER_SPOOF', 'holder_binding', identity.reason!, timings, res);
        const credential = identity.derivedVc;

        if(credential.issuer !== issuerDid && credential.issuer?.id !== issuerDid) {
          return fail(state, 400, 'UNTRUSTED_ISSUER', 'issuer_proof', 'issuer khong nam trong danh sach tin cay', timings, res);
        }
        if(!Number.isFinite(Date.parse(credential.validFrom)) || Date.parse(credential.validFrom) > Date.now() ||
          (session.type === 'CourseCertificateCredential' && !credential.validUntil) ||
          (credential.validUntil && (!Number.isFinite(Date.parse(credential.validUntil)) || Date.parse(credential.validUntil) <= Date.now()))) {
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
        const issue = checkPresentationProfile(credential, session.type, session.wanted);
        if(issue) return fail(state, 400, 'INCOMPLETE', 'issuer_proof', issue, timings, res);
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
        const entriesToCheck = Array.isArray(credential.credentialStatus) ? credential.credentialStatus : [credential.credentialStatus];
        const revocation = entriesToCheck.find(entry => entry?.statusPurpose === 'revocation');
        const suspension = entriesToCheck.find(entry => entry?.statusPurpose === 'suspension');
        if(!revocation || (Array.isArray(credential.credentialStatus) && (!suspension || entriesToCheck.length !== 2 ||
          revocation.statusListIndex !== suspension.statusListIndex))) {
          return fail(state, 400, 'INCOMPLETE', 'status', 'Cấu trúc trạng thái không hợp lệ', timings, res);
        }
        let status: Awaited<ReturnType<VerifierStatusCache['check']>>;
        try {
          status = await statusCache.check({credentialStatus: revocation});
          if(status.verified && suspension) status = await suspensionCache.check({credentialStatus: suspension});
        } catch {
          throw new HttpError(503, 'Không kiểm tra được danh sách trạng thái');
        }
        timings.statusMs = performance.now() - t;
        if(!status.verified) return fail(state, 400, 'REVOKED', 'status', status.reason!, timings, res);
        if(!liveSession(state)) throw new HttpError(400, 'Phiên đã hết hạn');
        t = performance.now();
        const first = await guard.consume(nonce, client_id);
        timings.redisMs = performance.now() - t;
        if(!first) return fail(state, 409, 'REPLAY', 'replay', 'Phiên đã hoàn tất', timings, res);
        session.done = true;

        const activeVerifierName = session.verifierName || verifierName;
        const receipt = signReceipt({aud: activeVerifierName, digest: legacyDigest, exp: Math.floor(Date.now() / 1000) + 600});
        session.receipt = receipt;
        session.legacyDigest = legacyDigest;
        const legacyDocUrl = legacyDigest ? `${publicUrl}/api/verifier/legacy-scan/${state}` : undefined;
        await portal.recordVerification({
          state,
          at: new Date().toISOString(),
          orgId: session.orgId || 'demo',
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
      if(!demoMode && ['/index.html', '/demo'].includes(url.pathname)) return send(res, 404, {error: 'not found'});
      if(req.method === 'GET' && serveStatic(res, publicDir, url.pathname, 'verifier.html')) return;
      return send(res, 404, {error: 'not found'});
    } catch(err: any) {
      return send(res, err instanceof HttpError || err instanceof RequestBodyError ? err.status : err?.status === 503 ? 503 : 500, {error: err instanceof HttpError || err instanceof RequestBodyError ? err.message : 'Không xử lý được yêu cầu xác minh'});
    }
  });

  await new Promise<void>(r => server.listen(port, opts.demoMode ? '127.0.0.1' : '0.0.0.0', r));
  return {
    server, baseUrl: publicUrl, clientId, issuerDid, statusCache, guard, documentLoader, docs,
    close: async () => { guard.close(); server.closeAllConnections?.(); await new Promise<void>(r => server.close(() => r())); await docs.close(); }
  };
}
