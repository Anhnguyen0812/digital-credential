import * as http from 'node:http';
import * as path from 'node:path';
import {WalletClient} from './wallet-client-sdk.js';
import {readBody, send, preflight, serveStatic, CORS_HEADERS} from './http-util.js';
import {createWalletPortal} from '../portal/wallet-portal.js';

export interface WalletAppOptions {
  port?: number;
  issuerPublicUrl?: string;
  verifierPublicUrl?: string;
  issuerInternalUrl?: string;
  verifierInternalUrl?: string;
  wallet?: WalletClient;
}

function proxyRequest(req: http.IncomingMessage, res: http.ServerResponse, targetBase: string) {
  const target = new URL(req.url || '/', targetBase);
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
  const verifierPublicUrl = opts.verifierPublicUrl ?? 'http://localhost:4002';
  const issuerInternalUrl = opts.issuerInternalUrl ?? issuerPublicUrl;
  const verifierInternalUrl = opts.verifierInternalUrl ?? verifierPublicUrl;
  const wallet = opts.wallet ?? await WalletClient.create();
  const publicDir = path.resolve(process.cwd(), 'public');
  const portal = createWalletPortal({wallet, issuerInternalUrl});

  const toInternal = (u: string) => {
    if(u.startsWith(verifierPublicUrl)) return verifierInternalUrl + u.slice(verifierPublicUrl.length);
    if(u.startsWith(issuerPublicUrl)) return issuerInternalUrl + u.slice(issuerPublicUrl.length);
    if(u.startsWith('/api/verifier/')) return verifierInternalUrl + u;
    if(u.startsWith('/api/issuer/') || u.startsWith('/status/') || u.startsWith('/api/legacy/')) return issuerInternalUrl + u;
    try {
      const parsed = new URL(u);
      if(parsed.pathname.startsWith('/api/verifier/')) return verifierInternalUrl + parsed.pathname + parsed.search;
      if(parsed.pathname.startsWith('/api/issuer/') || parsed.pathname.startsWith('/status/') || parsed.pathname.startsWith('/api/legacy/')) {
        return issuerInternalUrl + parsed.pathname + parsed.search;
      }
    } catch {}
    throw new Error('URL khong nam trong allowlist cua vi: ' + u);
  };

  const server = http.createServer(async (req, res) => {
    if(preflight(req, res)) return;
    const url = new URL(req.url || '/', `http://localhost:${port}`);
    try {
      if(req.method === 'GET' && url.pathname === '/health') return send(res, 200, {ok: true, service: 'wallet'});
      if(req.method === 'GET' && url.pathname === '/config.json') {
        return send(res, 200, {
          issuerUrl: issuerPublicUrl,
          verifierUrl: verifierPublicUrl,
          unifiedProxy: true
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

      if(req.method === 'GET' && url.pathname === '/api/wallet/info') {
        return send(res, 200, {
          did: wallet.did,
          badge: 'P-256 Multikey Active • Non-Custodial Wallet Agent (Khóa bí mật cô lập hoàn toàn)',
          nonCustodial: true,
          credentials: wallet.listCredentials()
        });
      }

      if(req.method === 'POST' && url.pathname === '/api/wallet/receive') {
        const body = await readBody(req);
        if(!body.id || !body.credential) return send(res, 400, {error: 'thieu id/credential'});
        if(body.credential?.credentialSubject?.id !== wallet.did) return send(res, 400, {error: 'chung chi khong danh cho DID cua vi nay'});
        wallet.addCredential(body.id, body.credential);
        return send(res, 201, {stored: body.id, credentials: wallet.listCredentials()});
      }

      if(req.method === 'GET' && url.pathname === '/api/wallet/backup') {
        return send(res, 200, await wallet.exportBackup());
      }

      if(req.method === 'POST' && url.pathname === '/api/wallet/restore') {
        const body = await readBody(req);
        const r = await wallet.restoreBackup(body);
        return send(res, 200, r);
      }

      if(req.method === 'POST' && url.pathname === '/api/wallet/rotate-device') {
        const r = await wallet.rotateNewDevice();
        return send(res, 200, r);
      }

      let m = /^\/api\/wallet\/credential\/([\w-]+)$/.exec(url.pathname);
      if(req.method === 'GET' && m) {
        const vc = wallet.getBaseCredential(m[1]);
        return vc ? send(res, 200, vc) : send(res, 404, {error: 'khong co chung chi'});
      }

      // Quet QR: lay request object tu request_uri
      if(req.method === 'POST' && url.pathname === '/api/wallet/scan') {
        const body = await readBody(req);
        const r = await fetch(toInternal(body.request_uri));
        if(!r.ok) return send(res, 400, {error: 'khong tai duoc request_uri'});
        return send(res, 200, {request: await r.json()});
      }

      if(req.method === 'POST' && url.pathname === '/api/wallet/preview') {
        const body = await readBody(req);
        return send(res, 200, wallet.preview(body.request, body.credentialId));
      }

      if(req.method === 'POST' && url.pathname === '/api/wallet/present') {
        const body = await readBody(req);
        if(body.consent !== true) return send(res, 400, {error: 'nguoi hoc chua chap thuan chia se'});
        const prev = wallet.preview(body.request, body.credentialId);
        const out = await wallet.present({
          request: body.request, credentialId: body.credentialId, approvedClaims: body.approvedClaims,
          consent: true, simulate: body.simulate
        });
        let submitted: any;
        if(body.submit) {
          const r = await fetch(toInternal(body.request.response_uri), {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({state: out.state, vp_token: out.vp_token})
          });
          submitted = {status: r.status, body: await r.json()};
        }
        wallet.recordHistory({
          credentialId: body.credentialId,
          verifier: body.request?.verifier_name || body.request?.client_id || 'Verifier',
          disclosedClaims: [...prev.mandatory, ...out.disclosedClaims],
          hiddenClaims: prev.hidden,
          deriveMs: out.deriveMs,
          signMs: out.signMs,
          status: submitted?.status
        });
        return send(res, 200, {...out, submitted});
      }

      if(req.method === 'GET' && serveStatic(res, publicDir, url.pathname)) return;
      return send(res, 404, {error: 'not found'});
    } catch(err: any) {
      return send(res, 500, {error: err?.message || String(err)});
    }
  });

  await new Promise<void>(r => server.listen(port, '0.0.0.0', r));
  return {server, wallet, close: async () => { server.closeAllConnections?.(); await new Promise<void>(r => server.close(() => r())); }};
}
