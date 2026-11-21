import {describe, it, expect, beforeAll, afterAll} from 'vitest';
import {createIssuerApp} from '../src/services/issuer-app.js';
import {createVerifierApp} from '../src/services/verifier-app.js';
import {createWalletApp} from '../src/services/wallet-app.js';
import {DEMO_PASSWORD} from '../src/portal/seed-data.js';

let walCookie: string;

function extractCookie(res: Response, name: string): string {
  const raw = res.headers.getSetCookie?.() || [res.headers.get('set-cookie') || ''];
  for (const h of raw) {
    if (h.startsWith(name + '=')) return h.split(';')[0];
  }
  return '';
}

describe('W6 - Hệ thống 3 Web Portal độc lập: Đăng nhập scrypt, Session HttpOnly, RBAC 4 mắt, OpenID4VCI PoP & AES-256-GCM Backup', () => {
  let issuer: Awaited<ReturnType<typeof createIssuerApp>>;
  let verifier: Awaited<ReturnType<typeof createVerifierApp>>;
  let walletApp: Awaited<ReturnType<typeof createWalletApp>>;

  beforeAll(async () => {
    issuer = await createIssuerApp({port: 14101, publicUrl: 'http://localhost:14101'});
    verifier = await createVerifierApp({
      port: 14102,
      publicUrl: 'http://localhost:14102',
      issuerPublicUrl: 'http://localhost:14101',
      issuerInternalUrl: 'http://localhost:14101'
    });
    walletApp = await createWalletApp({
      port: 14100,
      issuerPublicUrl: 'http://localhost:14101',
      verifierPublicUrl: 'http://localhost:14102',
      issuerInternalUrl: 'http://localhost:14101',
      verifierInternalUrl: 'http://localhost:14102'
    });
  });

  afterAll(async () => {
    await walletApp?.close();
    await verifier?.close();
    await issuer?.close();
  });

  it('W6.1 - Đăng nhập Cổng Nhà trường (scrypt + HttpOnly cookie) & Kiểm soát RBAC nghiêm ngặt giữa Chuyên viên và Trưởng phòng', async () => {
    // 1. Chuyen vien dang nhap
    const regLogin = await fetch('http://localhost:14101/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'chuyenvien', password: DEMO_PASSWORD})
    });
    expect(regLogin.status).toBe(200);
    const regCookie = extractCookie(regLogin, 'iss_sid');
    expect(regCookie).toContain('iss_sid=');

    // 2. Chuyen vien co tinh duyet ho so -> Bi chan HTTP 403 RBAC_FORBIDDEN
    const tryApprove = await fetch('http://localhost:14101/api/portal/records/rec-deg-23020114/approve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: regCookie},
      body: JSON.stringify({note: 'tu duyet'})
    });
    expect(tryApprove.status).toBe(403);
    const errBody = await tryApprove.json();
    expect(errBody.code).toBe('RBAC_FORBIDDEN');

    // 3. Truong phong dang nhap -> Phê duyệt thành công
    const appLogin = await fetch('http://localhost:14101/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'truongphong', password: DEMO_PASSWORD})
    });
    expect(appLogin.status).toBe(200);
    const appCookie = extractCookie(appLogin, 'iss_sid');

    const okApprove = await fetch('http://localhost:14101/api/portal/records/rec-deg-23020114/approve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: appCookie},
      body: JSON.stringify({note: 'Đã đối chiếu quyết định tốt nghiệp'})
    });
    expect(okApprove.status).toBe(200);
    const approvedRec = (await okApprove.json()).record;
    expect(approvedRec.status).toBe('APPROVED');
    expect(approvedRec.approvedBy).toBe('truongphong');
  });

  it('W6.2 - Cựu sinh viên đã bị thu hồi Email trường bị chặn khi đăng nhập SSO nhưng đăng nhập thành công bằng VNeID (CCCD)', async () => {
    // Cuu sinh vien K56 (11020345@vnu.edu.vn) da bi thu hoi email sau tot nghiep
    const ssoAttempt = await fetch('http://localhost:14100/api/wallet-portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({method: 'sso', identifier: '11020345@vnu.edu.vn', password: DEMO_PASSWORD})
    });
    expect(ssoAttempt.status).toBe(403);
    const ssoErr = await ssoAttempt.json();
    expect(ssoErr.code).toBe('EMAIL_DEACTIVATED');

    // Dang nhap bang VNeID (so CCCD 001193005566) -> Thanh cong
    const vneidLogin = await fetch('http://localhost:14100/api/wallet-portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({method: 'vneid', identifier: '001193005566', password: DEMO_PASSWORD})
    });
    expect(vneidLogin.status).toBe(200);
    const vneidData = await vneidLogin.json();
    expect(vneidData.student.studentCode).toBe('11020345');
  });

  it('W6.3 - Sinh viên đăng nhập Ví, ký Proof-of-Possession (OpenID4VCI) nhận văn bằng & Sao lưu mã hóa AES-256-GCM khi đổi điện thoại', async () => {
    const stuLogin = await fetch('http://localhost:14100/api/wallet-portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({method: 'sso', identifier: '23020009@vnu.edu.vn', password: DEMO_PASSWORD})
    });
    expect(stuLogin.status).toBe(200);
    walCookie = extractCookie(stuLogin, 'wal_sid');

    // Nhan van bang da duoc duyet (rec-deg-23020009) bang chu ky PoP tren c_nonce
    const claimRes = await fetch('http://localhost:14100/api/wallet-portal/claim', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: walCookie},
      body: JSON.stringify({recordId: 'rec-deg-23020009'})
    });
    expect(claimRes.status).toBe(200);
    const claimed = await claimRes.json();
    expect(claimed.credential.credentialSubject.id).toBe(claimed.walletDid);

    // Xuat ban sao luu ma hoa AES-256-GCM
    const expRes = await fetch('http://localhost:14100/api/wallet-portal/backup/export', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: walCookie},
      body: JSON.stringify({passphrase: 'SecretPass@2026', password: DEMO_PASSWORD})
    });
    const encryptedBundle = await expRes.json();
    expect(encryptedBundle.cipher).toBe('aes-256-gcm');

    // Mo phong doi sang dien thoai moi (sinh did:key moi)
    const rotRes = await fetch('http://localhost:14100/api/wallet-portal/device/rotate', {method: 'POST', headers: {'Content-Type': 'application/json', Cookie: walCookie}, body: JSON.stringify({password: DEMO_PASSWORD})});
    const rotData = await rotRes.json();
    expect(rotData.newDid).not.toBe(claimed.walletDid);

    // Khoi phuc tu ban sao luu AES-256-GCM
    const restRes = await fetch('http://localhost:14100/api/wallet-portal/backup/restore', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: walCookie},
      body: JSON.stringify({bundle: encryptedBundle, passphrase: 'SecretPass@2026', password: DEMO_PASSWORD})
    });
    expect(restRes.status).toBe(200);
    const restData = await restRes.json();
    expect(restData.did).toBe(claimed.walletDid);
    expect(restData.count).toBeGreaterThanOrEqual(1);
  });

  it('W6.4 - Doanh nghiệp đăng nhập Cổng Tuyển dụng, tạo phiên xác minh & lưu lịch sử hậu kiểm', async () => {
    const rpLogin = await fetch('http://localhost:14102/api/rp/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'hr.viettel', password: DEMO_PASSWORD})
    });
    expect(rpLogin.status).toBe(200);
    const rpCookie = extractCookie(rpLogin, 'rp_sid');

    const reqRes = await fetch('http://localhost:14102/api/verifier/request', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: rpCookie},
      body: JSON.stringify({credentialType: 'DegreeCredential', claims: ['major', 'gpa']})
    });
    const reqData = await reqRes.json();
    expect(reqData.request.verifier_name).toContain('Viettel Cyber Security');

    const preview = await fetch('http://localhost:14100/api/wallet/preview', {
      method: 'POST', headers: {'Content-Type': 'application/json', Cookie: walCookie},
      body: JSON.stringify({request: reqData.request, credentialId: 'rec-deg-23020009'})
    });
    expect(preview.status).toBe(200);
    const {consentId} = await preview.json();

    // Sinh vien trinh bay tu Vi
    const presRes = await fetch('http://localhost:14100/api/wallet/present', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: walCookie},
      body: JSON.stringify({
        request: reqData.request,
        credentialId: 'rec-deg-23020009',
        consent: true, consentId,
        submit: true
      })
    });
    const presData = await presRes.json();
    expect(presData.submitted.status).toBe(200);

    // Kiem tra lich su xac minh tren Cong Tuyen dung
    const histRes = await fetch('http://localhost:14102/api/rp/verifications', {
      headers: {Cookie: rpCookie}
    });
    expect(histRes.status).toBe(200);
    const histData = await histRes.json();
    expect(histData.items.length).toBeGreaterThanOrEqual(1);
    expect(histData.items[0].verified).toBe(true);
    expect(histData.items[0].verifierName).toContain('Viettel Cyber Security');
  });

  it('Bảo vệ quyền truy cập mặc định và cô lập ví giữa hai sinh viên', async () => {
    const base = 'http://localhost:14100';
    const guarded = [
      ['/api/issuer/issue-degree', 'POST', 404],
      ['/api/issuer/revoke', 'POST', 404],
      ['/api/wallet/backup', 'GET', 404],
      ['/api/wallet-portal/backup/export', 'POST', 401],
      ['/api/wallet/info', 'GET', 401],
      ['/api/verifier/request', 'POST', 401],
      ['/api/verifier/latest', 'GET', 404],
    ] as const;
    for(const [route, method, status] of guarded) {
      expect((await fetch(base + route, {method})).status).toBe(status);
    }
    const guest = await (await fetch(base + '/api/wallet-portal/me')).json();
    expect(guest.wallet).toEqual({did: null, credentials: [], history: []});
    const signin = await fetch(base + '/api/wallet-portal/auth/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({method: 'sso', identifier: '23020114@vnu.edu.vn', password: DEMO_PASSWORD})
    });
    expect(signin.status).toBe(200);
    const secondCookie = extractCookie(signin, 'wal_sid');
    const second = await signin.json();
    const first = await (await fetch(base + '/api/wallet/info', {headers: {Cookie: walCookie}})).json();
    expect(second.walletDid).not.toBe(first.did);
    const record = await fetch(base + '/api/wallet/credential/rec-deg-23020009', {headers: {Cookie: secondCookie}});
    expect(record.status).toBe(404);
  });

  it('Lịch sử, biên bản và SSE tuân theo tổ chức của phiên', async () => {
    const base = 'http://localhost:14102';
    async function login(username: string) {
      const response = await fetch(base + '/api/rp/auth/login', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password: DEMO_PASSWORD})
      });
      expect(response.status).toBe(200);
      return extractCookie(response, 'rp_sid');
    }
    const fpt = await login('hr.fpt');
    const viettel = await login('hr.viettel');
    const list = await (await fetch(base + '/api/rp/verifications', {headers: {Cookie: viettel}})).json();
    const verified = list.items.find((item: any) => item.verified);
    expect(verified).toBeDefined();
    expect((await (await fetch(base + '/api/rp/verifications', {headers: {Cookie: fpt}})).json()).items).toEqual([]);
    for(const path of [
      '/api/rp/verifications/' + verified.state,
      '/api/rp/verifications/' + verified.state + '/receipt',
      '/api/verifier/events?state=' + verified.state,
      '/api/verifier/legacy-scan/' + verified.state
    ]) {
      expect((await fetch(base + path, {headers: {Cookie: fpt}})).status).toBe(404);
    }
  });

});
