import type {WalletClient} from '../services/wallet-client-sdk.js';
import {SessionManager} from '../auth/session.js';
import {Router, HttpError, required} from './router.js';

interface StudentSession {
  student: any;
  token: string;
  method: 'sso' | 'vneid';
}

export function createWalletPortal(opts: {
  wallet: WalletClient;
  issuerInternalUrl: string;
}) {
  const {wallet, issuerInternalUrl} = opts;
  const sessions = new SessionManager<StudentSession>('wal_sid');
  const router = new Router();

  router.post('/api/wallet-portal/auth/login', async ctx => {
    required(ctx.body, ['method', 'identifier', 'password']);
    const r = await fetch(`${issuerInternalUrl}/api/student-auth/login`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(ctx.body)
    });
    const data = await r.json();
    if (!r.ok) throw new HttpError(r.status, data?.error || 'Đăng nhập thất bại', data?.code);
    sessions.create({student: data.student, token: data.token, method: data.method}, ctx.req, ctx.res);
    return {student: data.student, method: data.method, walletDid: wallet.did};
  });

  router.post('/api/wallet-portal/auth/logout', async ctx => {
    sessions.destroy(ctx.req, ctx.res);
    return {ok: true};
  });

  router.get('/api/wallet-portal/me', async ctx => {
    const s = sessions.get(ctx.req);
    let issuerRecords: any[] = [];
    let issuerDid = '';
    let student = s?.user.student ?? null;
    if (s) {
      try {
        const r = await fetch(`${issuerInternalUrl}/api/student/me`, {
          headers: {Authorization: `Bearer ${s.user.token}`}
        });
        if (r.ok) {
          const d = await r.json();
          issuerRecords = d.records || [];
          issuerDid = d.issuerDid || '';
          if (d.student) student = d.student;
        }
      } catch {}
    }
    return {
      authenticated: !!s,
      student,
      method: s?.user.method ?? null,
      issuerDid,
      issuerRecords,
      wallet: {
        did: wallet.did,
        credentials: wallet.listCredentials(),
        history: wallet.getHistory()
      }
    };
  });

  router.post('/api/wallet-portal/claim', async ctx => {
    const s = sessions.get(ctx.req);
    if (!s) throw new HttpError(401, 'Vui lòng đăng nhập định danh sinh viên trước khi nhận văn bằng', 'UNAUTHENTICATED');
    required(ctx.body, ['recordId']);

    // Buoc 1: Xin c_nonce tu Issuer (OpenID4VCI)
    const nr = await fetch(`${issuerInternalUrl}/api/student/nonce`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Authorization: `Bearer ${s.user.token}`},
      body: '{}'
    });
    const nd = await nr.json();
    if (!nr.ok) throw new HttpError(nr.status, nd?.error || 'Không lấy được c_nonce từ cổng nhà trường');

    // Buoc 2: Vi ky Proof-of-Possession tren c_nonce bang khoa rieng P-256
    const proof = await wallet.signOpenId4VciProof(nd.c_nonce, nd.aud);

    // Buoc 3: Gui yeu cau nhan van bang kem PoP
    const cr = await fetch(`${issuerInternalUrl}/api/student/claim`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Authorization: `Bearer ${s.user.token}`},
      body: JSON.stringify({
        recordId: ctx.body.recordId,
        holderDid: wallet.did,
        c_nonce: nd.c_nonce,
        proof
      })
    });
    const cd = await cr.json();
    if (!cr.ok) throw new HttpError(cr.status, cd?.error || 'Nhận văn bằng thất bại', cd?.code);

    wallet.addCredential(cd.recordId, cd.credential);
    return {
      recordId: cd.recordId,
      statusListIndex: cd.statusListIndex,
      credential: cd.credential,
      walletDid: wallet.did
    };
  });

  router.post('/api/wallet-portal/reissue', async ctx => {
    const s = sessions.get(ctx.req);
    if (!s) throw new HttpError(401, 'Vui lòng đăng nhập trước khi gửi yêu cầu cấp lại', 'UNAUTHENTICATED');
    required(ctx.body, ['recordId', 'reason']);
    const r = await fetch(`${issuerInternalUrl}/api/student/reissue`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Authorization: `Bearer ${s.user.token}`},
      body: JSON.stringify({recordId: ctx.body.recordId, reason: ctx.body.reason})
    });
    const d = await r.json();
    if (!r.ok) throw new HttpError(r.status, d?.error || 'Không gửi được yêu cầu cấp lại');
    return d;
  });

  router.post('/api/wallet-portal/backup/export', async ctx => {
    const passphrase = typeof ctx.body?.passphrase === 'string' ? ctx.body.passphrase.trim() : undefined;
    return await wallet.exportBackup(passphrase || undefined);
  });

  router.post('/api/wallet-portal/backup/restore', async ctx => {
    required(ctx.body, ['bundle']);
    const passphrase = typeof ctx.body?.passphrase === 'string' ? ctx.body.passphrase.trim() : undefined;
    try {
      return await wallet.restoreBackup(ctx.body.bundle, passphrase || undefined);
    } catch (e: any) {
      throw new HttpError(400, e?.message || 'Khôi phục Ví thất bại');
    }
  });

  router.post('/api/wallet-portal/device/rotate', async () => {
    return await wallet.rotateNewDevice();
  });

  return {router, sessions};
}
