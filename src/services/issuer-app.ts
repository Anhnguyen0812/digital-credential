import * as http from 'node:http';
import * as path from 'node:path';
import {createHash} from 'node:crypto';
import {createCustomDocumentLoader, createLoaderRegistry} from '../context/document-loader.js';
import {generateIssuerKeys, registerKey} from '../crypto/multikey-manager.js';
import {issueSelectiveDisclosureVc} from '../crypto/holder-binding.js';
import {computeDocumentDigest, signLegacyProvenance} from '../crypto/provenance-signer.js';
import {
  buildUnsignedDegreeVc, DEGREE_MANDATORY_POINTERS, LEGACY_DEGREE_MANDATORY_POINTERS
} from '../profiles/degree-profile.js';
import {buildUnsignedCourseVc, COURSE_MANDATORY_POINTERS} from '../profiles/course-profile.js';
import {IssuerStatusRegistry} from '../status/status-store.js';
import {AuditStore, createAuditStore, newRecordId} from '../infra/postgres-store.js';
import {createOrGetSampleScanFile} from '../legacy-service.js';
import {readBody, send, preflight, serveStatic} from './http-util.js';
import {verifyReceipt} from './receipt-token.js';
import * as fs from 'node:fs';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {createDocStore, DocStore} from '../infra/doc-store.js';
import {createIssuerPortal} from '../portal/issuer-portal.js';

export interface IssuerOptions {
  port?: number;
  publicUrl?: string;            // URL cong khai (vd http://localhost:4001) -> did:web
  statusCacheSeconds?: number;
  store?: AuditStore;
  docs?: DocStore;
  scanFilePath?: string;
}

export function didWebFromUrl(publicUrl: string): string {
  const u = new URL(publicUrl);
  return 'did:web:' + encodeURIComponent(u.host).replace(/%3A/gi, '%3A');
}

function watermarkedSvg(params: {digest: string; digestMatch: boolean; viewer: string; at: string; bytes: number}) {
  const esc = (s: string) => s.replace(/[<&>"]/g, c => ({'<': '&lt;', '&': '&amp;', '>': '&gt;', '"': '&quot;'}[c] as string));
  const lines = Array.from({length: 6}, (_, i) =>
    `<text x="${-40 + i * 10}" y="${70 + i * 110}" transform="rotate(-24 300 300)" fill="#b42318" fill-opacity="0.22" font-size="26" font-family="monospace">${esc(params.viewer)} · ${esc(params.at)}</text>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="640" height="720" viewBox="0 0 640 720">
<rect width="640" height="720" fill="#fffdf7" stroke="#999"/>
<text x="32" y="50" font-size="20" font-family="serif" font-weight="bold">SỔ GỐC LƯU TRỮ - BẢN XEM TRƯỚC (PREVIEW)</text>
<text x="32" y="86" font-size="13" font-family="monospace">Tệp gốc: ${params.bytes} bytes (bản scan sổ đăng ký văn bằng 2015)</text>
<text x="32" y="112" font-size="13" font-family="monospace">sourceDocumentDigest: ${esc(params.digest.slice(0, 40))}…</text>
<text x="32" y="138" font-size="13" font-family="monospace" fill="${params.digestMatch ? '#127a3f' : '#b42318'}">SHA-256 khớp tệp gốc: ${params.digestMatch ? 'CÓ' : 'KHÔNG'}</text>
${lines}
<text x="32" y="690" font-size="12" font-family="monospace">Truy vấn bởi: ${esc(params.viewer)} lúc ${esc(params.at)} - tài liệu bảo vệ bằng watermark động</text>
</svg>`;
}

export async function createIssuerApp(opts: IssuerOptions = {}) {
  const port = opts.port ?? 4001;
  const publicUrl = opts.publicUrl ?? `http://localhost:${port}`;
  const issuerDid = didWebFromUrl(publicUrl);
  const statusUrl = `${publicUrl}/status/degree-list-1`;
  const cacheSeconds = opts.statusCacheSeconds ?? 300;

  const docs = opts.docs ?? await createDocStore({postgresUrl: process.env.POSTGRES_URL, table: 'issuer_documents'});
  const registry = createLoaderRegistry();
  const {issuerKeyPair, approverKeyPair} = await loadOrCreateIssuerKeys(docs, issuerDid);
  await registerKey(registry, issuerKeyPair);
  await registerKey(registry, approverKeyPair);
  const documentLoader = createCustomDocumentLoader(registry);
  const statusRegistry = new IssuerStatusRegistry(statusUrl, issuerKeyPair, documentLoader);
  await statusRegistry.publishSignedStatusList();
  const store = opts.store ?? await createAuditStore();

  const scanPath = opts.scanFilePath ?? path.resolve(process.cwd(), 'test-vectors', 'sample_ledger_2015.bin');
  createOrGetSampleScanFile(scanPath, 2_400_000);
  const scans = new Map<string, Buffer>();           // digest -> scan bytes
  const pending = new Map<string, any>();            // recordId -> ingest payload (PENDING_REVIEW)
  const credentials = new Map<string, any>();        // recordId -> base VC

  const sampleScan = () => fs.readFileSync(scanPath);
  async function getScan(digest: string): Promise<Buffer | undefined> {
    const hit = scans.get(digest);
    if(hit) return hit;
    const stored = await docs.get('scans', digest);
    if(stored?.b64) { const b = Buffer.from(stored.b64, 'base64'); scans.set(digest, b); return b; }
    const sample = sampleScan();
    if(computeDocumentDigest(sample) === digest) { scans.set(digest, sample); return sample; }
    return undefined;
  }

  const portal = await createIssuerPortal({
    docs, audit: store, statusRegistry, issuerKeyPair, approverKeyPair, documentLoader, issuerDid, statusUrl,
    sampleScan, registerScan: (dg, b) => scans.set(dg, b)
  });
  await portal.restoreStatus();

  const server = http.createServer(async (req, res) => {
    if(preflight(req, res)) return;
    const url = new URL(req.url || '/', publicUrl);
    try {
      if(req.method === 'GET' && url.pathname === '/health') return send(res, 200, {ok: true, service: 'issuer', db: store.mode});

      // ---- DID Document (did:web) ----
      if(req.method === 'GET' && url.pathname === '/.well-known/did.json') {
        return send(res, 200, registry.didDocuments.get(issuerDid), {'Cache-Control': 'public, max-age=300'});
      }

      // ---- Bitstring Status List + ETag ----
      if(req.method === 'GET' && url.pathname === '/status/degree-list-1') {
        const r = await statusRegistry.handleHttpGet(req.headers['if-none-match'] as string | undefined);
        const headers = {ETag: r.etag, 'Cache-Control': `public, max-age=${cacheSeconds}`};
        if(r.status === 304) { res.writeHead(304, {...headers, 'Access-Control-Allow-Origin': '*'}); return res.end(); }
        return send(res, 200, r.body, headers);
      }

      const issuerRole = String(req.headers['x-issuer-role'] || 'DEAN_APPROVER');
      const requireApprover = () => {
        if(issuerRole === 'STAFF_VERIFIER') {
          send(res, 403, {
            error: 'RBAC_FORBIDDEN: Tài khoản Chuyên viên Văn thư (STAFF_VERIFIER) chỉ có quyền nhập hồ sơ & scan, không có quyền đóng chữ ký số phát hành hoặc thu hồi văn bằng. Vui lòng chuyển sang tài khoản Trưởng phòng Đào tạo (DEAN_APPROVER).'
          });
          return false;
        }
        return true;
      };

      // ---- Cap bang tot nghiep (khong co so goc) ----
      if(req.method === 'POST' && url.pathname === '/api/issuer/issue-degree') {
        if(!requireApprover()) return;
        const body = await readBody(req);
        if(!body.holderDid) return send(res, 400, {error: 'thieu holderDid'});
        const index = statusRegistry.allocateIndex();
        const unsigned = buildUnsignedDegreeVc({holderDid: body.holderDid, statusListIndex: index, statusListUrl: statusUrl, issuerDid, subject: body.subject});
        const credential = await issueSelectiveDisclosureVc({unsignedCredential: unsigned, issuerKeyPair, mandatoryPointers: DEGREE_MANDATORY_POINTERS, documentLoader});
        const id = newRecordId();
        credentials.set(id, credential);
        await store.saveRecord({id, kind: 'degree', status: 'ISSUED', statusListIndex: index, holderDid: body.holderDid, createdAt: new Date().toISOString()});
        await store.audit('ISSUE_DEGREE', {recordId: id, statusListIndex: index, role: issuerRole});
        return send(res, 201, {recordId: id, statusListIndex: index, credential});
      }

      // ---- Cap chung chi khoa hoc ----
      if(req.method === 'POST' && url.pathname === '/api/issuer/issue-course') {
        if(!requireApprover()) return;
        const body = await readBody(req);
        if(!body.holderDid) return send(res, 400, {error: 'thieu holderDid'});
        const index = statusRegistry.allocateIndex();
        const unsigned = buildUnsignedCourseVc({holderDid: body.holderDid, statusListIndex: index, statusListUrl: statusUrl, issuerDid, validFrom: body.validFrom, validUntil: body.validUntil, subject: body.subject});
        const credential = await issueSelectiveDisclosureVc({unsignedCredential: unsigned, issuerKeyPair, mandatoryPointers: COURSE_MANDATORY_POINTERS, documentLoader});
        const id = newRecordId();
        credentials.set(id, credential);
        await store.saveRecord({id, kind: 'course', status: 'ISSUED', statusListIndex: index, holderDid: body.holderDid, createdAt: new Date().toISOString()});
        await store.audit('ISSUE_COURSE', {recordId: id, statusListIndex: index, role: issuerRole});
        return send(res, 201, {recordId: id, statusListIndex: index, credential});
      }

      // ---- Legacy buoc 1: chuyen vien nhap ho so + scan so goc (PENDING_REVIEW) ----
      if(req.method === 'POST' && url.pathname === '/api/issuer/legacy/ingest') {
        const body = await readBody(req);
        if(!body.holderDid) return send(res, 400, {error: 'thieu holderDid'});
        const scan = body.scanBase64 ? Buffer.from(body.scanBase64, 'base64') : fs.readFileSync(scanPath);
        const digest = computeDocumentDigest(scan);
        scans.set(digest, scan);
        const id = newRecordId();
        pending.set(id, {
          holderDid: body.holderDid, digest,
          originalIssueDate: body.originalIssueDate ?? '2015-06-25',
          registryBookNumber: body.registryBookNumber ?? 'BK-2015/0842',
          degreeSerial: body.degreeSerial ?? 'B15-004921',
          verifiedBy: body.verifiedBy ?? 'chuyenvien_daotao_01',
          subject: body.subject
        });
        await store.saveRecord({id, kind: 'legacy_degree', status: 'PENDING_REVIEW', holderDid: body.holderDid, digest, createdAt: new Date().toISOString()});
        await store.audit('LEGACY_INGEST', {recordId: id, role: issuerRole});
        return send(res, 201, {recordId: id, status: 'PENDING_REVIEW', sourceDocumentDigest: digest, scanBytes: scan.length, verifiedBy: body.verifiedBy ?? 'chuyenvien_daotao_01'});
      }

      // ---- Legacy buoc 2: Lanh dao Phong Dao tao ky duyet -> cap VC ----
      if(req.method === 'POST' && url.pathname === '/api/issuer/legacy/approve') {
        if(!requireApprover()) return;
        const body = await readBody(req);
        const p = pending.get(body.recordId);
        if(!p) return send(res, 404, {error: 'khong co ho so cho duyet'});
        const prov = await signLegacyProvenance({
          originalIssueDate: p.originalIssueDate, registryBookNumber: p.registryBookNumber, degreeSerial: p.degreeSerial,
          sourceDocumentType: 'paper_ledger_scan', sourceDocumentDigest: p.digest,
          verificationMethod: 'physical_ledger_reconciliation', verifiedBy: p.verifiedBy,
          approvedBy: body.approvedBy ?? 'truongphong_daotao_01', approvalTimestamp: new Date().toISOString(),
          approverDid: approverKeyPair.id
        }, approverKeyPair);
        const index = statusRegistry.allocateIndex();
        const unsigned = buildUnsignedDegreeVc({holderDid: p.holderDid, statusListIndex: index, statusListUrl: statusUrl, issuerDid, legacyProvenance: prov, subject: p.subject});
        const credential = await issueSelectiveDisclosureVc({unsignedCredential: unsigned, issuerKeyPair, mandatoryPointers: LEGACY_DEGREE_MANDATORY_POINTERS, documentLoader});
        pending.delete(body.recordId);
        credentials.set(body.recordId, credential);
        await store.updateRecord(body.recordId, {status: 'ISSUED', statusListIndex: index});
        await store.audit('LEGACY_APPROVE_ISSUE', {recordId: body.recordId, statusListIndex: index, role: issuerRole});
        return send(res, 201, {recordId: body.recordId, status: 'APPROVED', statusListIndex: index, credential});
      }

      if(req.method === 'GET' && url.pathname === '/api/issuer/records') {
        return send(res, 200, {db: store.mode, records: await store.listRecords(), auditEvents: await store.auditCount()});
      }

      // ---- Thu hoi ----
      if(req.method === 'POST' && url.pathname === '/api/issuer/revoke') {
        if(!requireApprover()) return;
        const body = await readBody(req);
        const idx = Number(body.statusListIndex);
        const {etag} = await statusRegistry.setRevoked(idx, true);
        await store.audit('REVOKE', {statusListIndex: idx, role: issuerRole});
        return send(res, 200, {revoked: idx, etag});
      }

      // ---- Ban scan so goc co dong dau mo dong (can Verification Receipt Token) ----
      const m = /^\/api\/legacy\/document\/(.+)$/.exec(url.pathname);
      if(req.method === 'GET' && m) {
        const digest = decodeURIComponent(m[1]);
        const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('receipt') || undefined;
        const claims = verifyReceipt(bearer);
        if(!claims) return send(res, 401, {error: 'thieu hoac sai Verification Receipt Token'});
        if(claims.digest && claims.digest !== digest) return send(res, 403, {error: 'token khong cap quyen cho tai lieu nay'});
        const scan = await getScan(digest);
        if(!scan) return send(res, 404, {error: 'khong tim thay tai lieu'});
        const actual = 'urn:sha256:' + createHash('sha256').update(scan).digest('hex');
        const svg = watermarkedSvg({digest, digestMatch: actual === digest, viewer: claims.aud, at: new Date().toISOString(), bytes: scan.length});
        await store.audit('LEGACY_DOCUMENT_VIEW', {aud: claims.aud});
        res.writeHead(200, {'Content-Type': 'image/svg+xml; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Access-Control-Expose-Headers': 'X-Document-Digest,X-Digest-Match', 'X-Document-Digest': digest, 'X-Digest-Match': String(actual === digest)});
        return res.end(svg);
      }

      if(await portal.router.handle(req, res, url)) return;

      const publicDir = path.resolve(process.cwd(), 'public');
      if(req.method === 'GET' && serveStatic(res, publicDir, url.pathname, 'issuer.html')) return;
      return send(res, 404, {error: 'not found'});
    } catch(err: any) {
      return send(res, 500, {error: err?.message || String(err)});
    }
  });

  await new Promise<void>(r => server.listen(port, '0.0.0.0', r));
  return {
    server, baseUrl: publicUrl, issuerDid, documentLoader, registry, statusRegistry, issuerKeyPair, approverKeyPair, store, docs,
    close: async () => { server.closeAllConnections?.(); await new Promise<void>(r => server.close(() => r())); await store.close(); await docs.close(); }
  };
}

// Khoa ky cua truong duoc luu ben vung (CSDL) de VC da cap van kiem tra duoc sau khi khoi dong lai.
// Trien khai that: dat khoa trong HSM / KMS, khong luu trong CSDL ung dung.
async function loadOrCreateIssuerKeys(docs: DocStore, issuerDid: string) {
  if(docs.mode !== 'memory') {
    const saved = await docs.get('keys', issuerDid);
    if(saved) return {issuerKeyPair: await EcdsaMultikey.from(saved.issuer), approverKeyPair: await EcdsaMultikey.from(saved.approver)};
  }
  const keys = await generateIssuerKeys(issuerDid);
  if(docs.mode !== 'memory') {
    await docs.put('keys', issuerDid, {
      issuer: await keys.issuerKeyPair.export({publicKey: true, secretKey: true, includeContext: true}),
      approver: await keys.approverKeyPair.export({publicKey: true, secretKey: true, includeContext: true})
    });
  }
  return keys;
}
