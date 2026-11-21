import * as http from 'node:http';
import * as path from 'node:path';
import {WalletClient, PresentationInputError} from './wallet-client-sdk.js';
import {readBody, RequestBodyError, send, preflight, serveStatic, CORS_HEADERS} from './http-util.js';
import {randomBytes, createHmac, timingSafeEqual} from 'node:crypto';
import {HttpError} from '../portal/router.js';
import {createDocStore, type DocStore} from '../infra/doc-store.js';
import {createWalletPortal} from '../portal/wallet-portal.js';

export interface WalletAppOptions {
  port?: number;
  issuerPublicUrl?: string;
  verifierPublicUrl?: string;
  issuerInternalUrl?: string;
  verifierInternalUrl?: string;
  wallet?: WalletClient;
  demoMode?: boolean;
  docs?: DocStore;
  walletKey?: string;
}

function respond(status: number, body: any, headers: Record<string, string> = {'Cache-Control': 'no-store'}) {
  return {status, body, headers};
}

function proxyRequest(req: http.IncomingMessage, res: http.ServerResponse, targetBase: string) {
  const incoming = new URL(req.url || '/', 'http://local.invalid');
  const target = new URL(targetBase);
  target.pathname = incoming.pathname;
  target.search = incoming.search;
  const proxyReq = http.request(
    target,
    {
      method: req.method,
      headers: {
        ...req.headers,
        host: target.host
      }
    },
    proxyRes => {
      const headers: Record<string, any> = {...proxyRes.headers, ...CORS_HEADERS};
      res.writeHead(proxyRes.statusCode || 502, headers);
      proxyRes.pipe(res);
    }
  );
  proxyReq.on('error', err => {
    if (!res.headersSent) send(res, 502, {error: 'upstream error: ' + err.message});
    else res.end();
  });
  req.pipe(proxyReq);
}

// wallet-agent: dich vu doc lap (cong rieng) giu khoa rieng cua holder + Base VC.
// Derive + ky Holder Binding chay tai day; Issuer/Verifier khong bao gio nhan Base VC khi trinh bay.
// Ho tro Unified Gateway Proxy de chay qua 1 cong HTTPS duy nhat (Cloudflare Tunnel / ngrok / Render).
export async function createWalletApp(opts: WalletAppOptions = {}) {
  const port = opts.port ?? 3000;
  const issuerPublicUrl = opts.issuerPublicUrl ?? 'http://localhost:4001';
  const verifierPublicUrl = opts.verifierPublicUrl?.replace(/\/+$/, '') ?? 'http://localhost:4002';
  const issuerInternalUrl = opts.issuerInternalUrl ?? issuerPublicUrl;
  const verifierInternalUrl = opts.verifierInternalUrl ?? verifierPublicUrl;
  const docs = opts.docs ?? await createDocStore({postgresUrl: process.env.WALLET_POSTGRES_URL, table: 'wallet_documents'});
  const demoMode = opts.demoMode === true && docs.mode === 'memory';
  const wallet = demoMode ? opts.wallet ?? await WalletClient.create() : undefined;
  const walletKey = opts.walletKey ?? process.env.WALLET_STORAGE_KEY ?? (docs.mode === 'memory' ? randomBytes(32).toString('hex') : undefined);
  if(!walletKey || walletKey.length < 32) throw new Error('WALLET_STORAGE_KEY cần ít nhất 32 ký tự');
  const publicDir = path.resolve(process.cwd(), 'public');
  const portal = createWalletPortal({docs, walletKey, demoWallet: wallet, issuerInternalUrl});
  const previewTtlMs = 120_000;
  const allowedOrigin = new URL(verifierPublicUrl).origin;

  async function fetchRequest(input: string) {
    let uri: URL;
    try { uri = new URL(input, verifierPublicUrl); }
    catch { throw new HttpError(400, 'Địa chỉ yêu cầu không hợp lệ'); }
    const match = /^\/api\/verifier\/request\/([\w-]+)$/.exec(uri.pathname);
    if(uri.origin !== allowedOrigin || !match || uri.username || uri.password || uri.search || uri.hash) {
      throw new HttpError(400, 'Yêu cầu phải thuộc cổng xác minh đã cấu hình');
    }
    const response = await fetch(new URL(uri.pathname, verifierInternalUrl), {
      redirect: 'error', signal: AbortSignal.timeout(5000)
    });
    if(!response.ok) throw new HttpError(400, 'Phiên xác minh không còn khả dụng');
    const request = await response.json();
    const responseUri = new URL('/api/verifier/direct-post', verifierPublicUrl).href;
    if(request.state !== match[1] || request.response_uri !== responseUri ||
      request.client_id !== 'redirect_uri:' + responseUri || request.response_mode !== 'direct_post' ||
      request.response_type !== 'vp_token' || typeof request.nonce !== 'string') {
      throw new HttpError(400, 'Thông tin ràng buộc của yêu cầu xác minh không hợp lệ');
    }
    return request;
  }

  async function checkedRequest(submitted: any) {
    if(demoMode) return submitted;
    if(typeof submitted?.state !== 'string' || !/^[\w-]+$/.test(submitted.state)) {
      throw new HttpError(400, 'Thiếu phiên xác minh hợp lệ');
    }
    const current = await fetchRequest('/api/verifier/request/' + submitted.state);
    if(JSON.stringify(current) !== JSON.stringify(submitted)) throw new HttpError(400, 'Yêu cầu đã thay đổi, vui lòng xem lại');
    return current;
  }

  const server = http.createServer(async (req, res) => {
    if(preflight(req, res)) return;
    const url = new URL(req.url || '/', `http://localhost:${port}`);
    try {
      if(req.method === 'GET' && url.pathname === '/health') return send(res, 200, {ok: true, service: 'wallet'});
      if(req.method === 'GET' && url.pathname === '/config.json') {
        return send(res, 200, {
          issuerUrl: issuerPublicUrl,
          verifierUrl: verifierPublicUrl,
          unifiedProxy: true,
          demoMode
        });
      }

      // Gateway proxy sang issuer-service va verifier-service (ho tro HTTPS Tunnel 1 cong duy nhat)
      if(
        url.pathname.startsWith('/api/issuer/') ||
        url.pathname.startsWith('/api/portal/') ||
        url.pathname.startsWith('/api/student-auth/') ||
        url.pathname.startsWith('/api/student/') ||
        url.pathname.startsWith('/status/') ||
        url.pathname === '/.well-known/did.json' ||
        url.pathname.startsWith('/api/legacy/')
      ) {
        return proxyRequest(req, res, issuerInternalUrl);
      }

      if(url.pathname.startsWith('/api/verifier/') || url.pathname.startsWith('/api/rp/')) {
        return proxyRequest(req, res, verifierInternalUrl);
      }

      if(await portal.router.handle(req, res, url)) return;

      if(url.pathname.startsWith('/api/wallet/')) {
        if(['/api/wallet/backup', '/api/wallet/restore', '/api/wallet/rotate-device', '/api/wallet/receive'].includes(url.pathname) && !demoMode) {
          return send(res, 404, {error: 'not found'});
        }
        const result = await portal.withWallet(req, async (activeWallet, student) => {
          if(req.method === 'GET' && url.pathname === '/api/wallet/info') {
            return respond(200, {did: activeWallet.did, nonCustodial: false, credentials: activeWallet.listCredentials()});
          }
          const match = /^\/api\/wallet\/credential\/([\w-]+)$/.exec(url.pathname);
          if(req.method === 'GET' && match) {
            const vc = activeWallet.getBaseCredential(match[1]);
            return vc ? respond(200, vc, {'Cache-Control': 'no-store'}) : respond(404, {error: 'Không có chứng chỉ'});
          }
          if(req.method !== 'POST') return respond(404, {error: 'not found'});
          const body = await readBody(req);
          if(demoMode && !student && url.pathname === '/api/wallet/receive') {
            if(!body.id || body.credential?.credentialSubject?.id !== activeWallet.did) return respond(400, {error: 'Sai DID hoặc thiếu chứng chỉ'});
            activeWallet.addCredential(body.id, body.credential);
            return respond(201, {stored: body.id, credentials: activeWallet.listCredentials()});
          }
          if(demoMode && !student && url.pathname === '/api/wallet/rotate-device') {
            return respond(200, await activeWallet.rotateNewDevice());
          }
          if(url.pathname === '/api/wallet/scan') {
            return respond(200, {request: await fetchRequest(body.request_uri)});
          }
          if(url.pathname === '/api/wallet/preview' || url.pathname === '/api/wallet/present') {
            const request = await checkedRequest(body.request);
            if(!activeWallet.getBaseCredential(body.credentialId)) return respond(404, {error: 'Không có chứng chỉ trong ví'});
            const preview = activeWallet.preview(request, body.credentialId);
            const consentMac = (expiry: number) => createHmac('sha256', walletKey)
              .update(JSON.stringify(['preview-v1', expiry, request, body.credentialId, activeWallet.did, student?.student.studentCode]))
              .digest();
            if(url.pathname.endsWith('/preview')) {
              const expiry = Date.now() + previewTtlMs;
              return respond(200, {...preview, consentId: expiry + '.' + consentMac(expiry).toString('base64url')});
            }
            const [expires, mac] = typeof body.consentId === 'string' ? body.consentId.split('.') : [];
            const expiry = Number(expires);
            const proof = Buffer.from(mac ?? '', 'base64url');
            const hasPreview = Number.isSafeInteger(expiry) && expiry > Date.now() && expiry <= Date.now() + previewTtlMs &&
              proof.length === 32 && timingSafeEqual(proof, consentMac(expiry));
            if(body.consent !== true || (!demoMode && !hasPreview)) {
              return respond(400, {error: 'Cần xác nhận yêu cầu đã xem trước'});
            }
            if(body.approvedClaims !== undefined && (!Array.isArray(body.approvedClaims) || body.approvedClaims.some(c => typeof c !== 'string'))) {
              return respond(400, {error: 'Danh sách thuộc tính không hợp lệ'});
            }
            const out = await activeWallet.present({
              request, credentialId: body.credentialId, approvedClaims: body.approvedClaims,
              consent: true, simulate: demoMode && !student ? body.simulate : undefined
            });
            let submitted: any;
            if(body.submit) {
              const response = await fetch(new URL('/api/verifier/direct-post', verifierInternalUrl), {
                method: 'POST',
                body: new URLSearchParams({state: out.state, vp_token: JSON.stringify(out.vp_token)}),
                redirect: 'error', signal: AbortSignal.timeout(10000)
              });
              submitted = {status: response.status, body: await response.json()};
            }
            activeWallet.recordHistory({
              credentialId: body.credentialId, verifier: request.verifier_name || request.client_id,
              disclosedClaims: [...preview.mandatory, ...out.disclosedClaims],
              hiddenClaims: [...preview.hidden, ...preview.requestedOptional.filter(c => !out.disclosedClaims.includes(c))],
              deriveMs: out.deriveMs, signMs: out.signMs, status: submitted?.status
            });
            return respond(200, {...out, submitted});
          }
          return respond(404, {error: 'not found'});
        });
        return send(res, result.status, result.body, result.headers);
      }

      if(!demoMode && ['/index.html', '/demo'].includes(url.pathname)) return send(res, 404, {error: 'not found'});
      if(req.method === 'GET' && serveStatic(res, publicDir, url.pathname, demoMode ? 'index.html' : 'wallet.html')) return;
      return send(res, 404, {error: 'not found'});
    } catch(err: any) {
      const inputError = err instanceof PresentationInputError;
      return send(res, inputError ? 400 : err instanceof HttpError || err instanceof RequestBodyError ? err.status : err?.status === 503 ? 503 : 500,
        {error: inputError || err instanceof HttpError || err instanceof RequestBodyError ? err.message : 'Không xử lý được yêu cầu ví'});
    }
  });

  await new Promise<void>(r => server.listen(port, opts.demoMode ? '127.0.0.1' : '0.0.0.0', r));
  return {server, wallet, close: async () => { server.closeAllConnections?.(); await new Promise<void>(r => server.close(() => r())); await docs.close(); }};
}
