import {WalletClient} from '../services/wallet-client-sdk.js';
import {SessionManager} from '../auth/session.js';
import type {DocStore} from '../infra/doc-store.js';
import {Router, HttpError, required, type RouteCtx} from './router.js';

interface StudentSession {
  student: any;
  token: string;
  method: 'sso' | 'vneid';
}

export function createWalletPortal(opts: {
  docs: DocStore;
  walletKey: string;
  demoWallet?: WalletClient;
  issuerInternalUrl: string;
}) {
  const {docs, walletKey, demoWallet, issuerInternalUrl} = opts;
  const sessions = new SessionManager<StudentSession>('wal_sid');
  const router = new Router();

  async function requireStudent(req: RouteCtx['req']) {
    const session = await sessions.getAsync(req);
    if(!session) throw new HttpError(401, 'Vui lòng đăng nhập Ví sinh viên');
    return session.user;
  }

  async function withWallet<T>(req: RouteCtx['req'], action: (wallet: WalletClient, student?: StudentSession) => Promise<T>) {
    if(demoWallet && !req.headers.cookie?.includes('wal_sid=')) return action(demoWallet);
    const student = await requireStudent(req);
    return studentWallet(student, action);
  }

  async function studentWallet<T>(student: StudentSession, action: (wallet: WalletClient, user: StudentSession) => Promise<T>) {
    const owner = student.student.studentCode;
    return docs.atomic(async () => {
      const saved = await docs.get('wallets', owner);
      const wallet = await WalletClient.create();
      if(saved) await wallet.restoreBackup(saved, walletKey, owner);
      const result = await action(wallet, student);
      await docs.put('wallets', owner, await wallet.exportBackup(walletKey, owner));
      return result;
    });
  }

  async function confirmIdentity(ctx: RouteCtx, user: StudentSession) {
    required(ctx.body, ['password']);
    const identifier = user.method === 'sso' ? user.student.email : user.student.nationalId;
    const response = await fetch(issuerInternalUrl + '/api/student-auth/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({method: user.method, identifier, password: ctx.body.password}),
      signal: AbortSignal.timeout(5000)
    });
    if(!response.ok) throw new HttpError(response.status === 429 ? 429 : 403, 'Không xác nhận được danh tính chủ ví');
  }

  router.post('/api/wallet-portal/auth/login', async ctx => {
    required(ctx.body, ['method', 'identifier', 'password']);
    const r = await fetch(`${issuerInternalUrl}/api/student-auth/login`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(ctx.body),
      signal: AbortSignal.timeout(5000)
    });
    const data = await r.json();
    if (!r.ok) throw new HttpError(r.status, data?.error || 'Đăng nhập thất bại', data?.code);
    const user = {student: data.student, token: data.token, method: data.method};
    const walletDid = await studentWallet(user, async wallet => wallet.did);
    await sessions.create(user, ctx.req, ctx.res);
    return {student: data.student, method: data.method, walletDid};
  });

  router.post('/api/wallet-portal/auth/logout', async ctx => {
    await sessions.destroy(ctx.req, ctx.res);
    return {ok: true};
  });

  router.get('/api/wallet-portal/me', async ctx => {
    const s = await sessions.getAsync(ctx.req);
    let issuerRecords: any[] = [];
    let issuerDid = '';
    let student = s?.user.student ?? null;
    if (s) {
      try {
        const r = await fetch(`${issuerInternalUrl}/api/student/me`, {
          headers: {Authorization: `Bearer ${s.user.token}`},
          signal: AbortSignal.timeout(5000)
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
      wallet: s ? await studentWallet(s.user, async wallet => ({
        did: wallet.did, credentials: wallet.listCredentials(), history: wallet.getHistory()
      })) : {did: null, credentials: [], history: []}
    };
  });

  router.post('/api/wallet-portal/claim', async ctx => {
    const s = await sessions.getAsync(ctx.req);
    if (!s) throw new HttpError(401, 'Vui lòng đăng nhập định danh sinh viên trước khi nhận văn bằng', 'UNAUTHENTICATED');
    required(ctx.body, ['recordId']);

    return studentWallet(s.user, async wallet => {
      // Buoc 1: Xin c_nonce tu Issuer (OpenID4VCI)
      const nr = await fetch(`${issuerInternalUrl}/api/student/nonce`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', Authorization: `Bearer ${s.user.token}`},
        body: '{}',
        signal: AbortSignal.timeout(5000)
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
        }),
        signal: AbortSignal.timeout(10000)
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
  });

  router.post('/api/wallet-portal/reissue', async ctx => {
    const s = await sessions.getAsync(ctx.req);
    if (!s) throw new HttpError(401, 'Vui lòng đăng nhập trước khi gửi yêu cầu cấp lại', 'UNAUTHENTICATED');
    required(ctx.body, ['recordId', 'reason']);
    const r = await fetch(`${issuerInternalUrl}/api/student/reissue`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Authorization: `Bearer ${s.user.token}`},
      body: JSON.stringify({recordId: ctx.body.recordId, reason: ctx.body.reason}),
      signal: AbortSignal.timeout(5000)
    });
    const d = await r.json();
    if (!r.ok) throw new HttpError(r.status, d?.error || 'Không gửi được yêu cầu cấp lại');
    return d;
  });

  function backupPassphrase(ctx: RouteCtx) {
    const value = ctx.body?.passphrase;
    if(typeof value !== 'string' || value.length < 12 || value.length > 256) {
      throw new HttpError(400, 'Mật khẩu sao lưu cần từ 12 đến 256 ký tự');
    }
    return value;
  }

  router.post('/api/wallet-portal/backup/export', async ctx => {
    const user = await requireStudent(ctx.req);
    const passphrase = backupPassphrase(ctx);
    await confirmIdentity(ctx, user);
    return studentWallet(user, async wallet => wallet.exportBackup(passphrase, user.student.studentCode));
  });

  router.post('/api/wallet-portal/backup/restore', async ctx => {
    const user = await requireStudent(ctx.req);
    required(ctx.body, ['bundle']);
    const passphrase = backupPassphrase(ctx);
    if(ctx.body.bundle?.version !== 'vnu-wallet-encrypted-v1') throw new HttpError(400, 'Cần bản sao lưu đã mã hóa');
    await confirmIdentity(ctx, user);
    return studentWallet(user, async wallet => {
      try {
        return await wallet.restoreBackup(ctx.body.bundle, passphrase, user.student.studentCode);
      } catch(error: any) {
        throw new HttpError(400, error.message);
      }
    });
  });

  router.post('/api/wallet-portal/device/rotate', async ctx => {
    const user = await requireStudent(ctx.req);
    await confirmIdentity(ctx, user);
    return studentWallet(user, wallet => wallet.rotateNewDevice());
  });

  return {router, sessions, withWallet};
}
