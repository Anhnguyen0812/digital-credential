import {describe, it, expect, beforeAll, afterAll} from 'vitest';
import {createIssuerApp} from '../src/services/issuer-app.js';
import {createVerifierApp} from '../src/services/verifier-app.js';
import {createWalletApp} from '../src/services/wallet-app.js';
import {DEMO_PASSWORD} from '../src/portal/seed-data.js';

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
    const walCookie = extractCookie(stuLogin, 'wal_sid');

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
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({passphrase: 'SecretPass@2026'})
    });
    const encryptedBundle = await expRes.json();
    expect(encryptedBundle.cipher).toBe('aes-256-gcm');

    // Mo phong doi sang dien thoai moi (sinh did:key moi)
    const rotRes = await fetch('http://localhost:14100/api/wallet-portal/device/rotate', {method: 'POST'});
    const rotData = await rotRes.json();
    expect(rotData.newDid).not.toBe(claimed.walletDid);

    // Khoi phuc tu ban sao luu AES-256-GCM
    const restRes = await fetch('http://localhost:14100/api/wallet-portal/backup/restore', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({bundle: encryptedBundle, passphrase: 'SecretPass@2026'})
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

    // Sinh vien trinh bay tu Vi
    const presRes = await fetch('http://localhost:14100/api/wallet/present', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        request: reqData.request,
        credentialId: 'rec-deg-23020009',
        consent: true,
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
});
