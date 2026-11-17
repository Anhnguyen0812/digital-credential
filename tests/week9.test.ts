import {SessionManager} from '../src/auth/session.js';
import {describe, it, expect, beforeAll, afterAll} from 'vitest';
import {createIssuerApp} from '../src/services/issuer-app.js';
import {createVerifierApp} from '../src/services/verifier-app.js';
import {createWalletApp} from '../src/services/wallet-app.js';
import {DEMO_PASSWORD} from '../src/portal/seed-data.js';
import {unsealMultikey} from '../src/crypto/key-vault.js';

function extractCookie(res: Response, name: string): string {
  const raw = res.headers.getSetCookie?.() || [res.headers.get('set-cookie') || ''];
  for (const h of raw) {
    if (h.startsWith(name + '=')) return h.split(';')[0];
  }
  return '';
}

function extractCookieValue(cookieHeader: string, name: string): string {
  const prefix = name + '=';
  if (cookieHeader.startsWith(prefix)) return decodeURIComponent(cookieHeader.slice(prefix.length));
  return '';
}

describe('W9 - Nâng cấp Tuần 9 (Từ Khảo sát Hệ thống Thực tế): Dynamic RBAC, Batch CSV Import, RedisSessionStore, KeyVault AES-256-GCM, Suspend/Reinstate, OIDC/VNeID ES256 & Verification Receipt', () => {
  let issuer: Awaited<ReturnType<typeof createIssuerApp>>;
  let verifier: Awaited<ReturnType<typeof createVerifierApp>>;
  let walletApp: Awaited<ReturnType<typeof createWalletApp>>;

  beforeAll(async () => {
    issuer = await createIssuerApp({port: 14201, publicUrl: 'http://localhost:14201'});
    verifier = await createVerifierApp({
      port: 14202,
      publicUrl: 'http://localhost:14202',
      issuerPublicUrl: 'http://localhost:14201',
      issuerInternalUrl: 'http://localhost:14201'
    });
    walletApp = await createWalletApp({
      port: 14200,
      issuerPublicUrl: 'http://localhost:14201',
      verifierPublicUrl: 'http://localhost:14202',
      issuerInternalUrl: 'http://localhost:14201',
      verifierInternalUrl: 'http://localhost:14202'
    });
  });

  afterAll(async () => {
    await walletApp?.close();
    await verifier?.close();
    await issuer?.close();
  });

  it('W9.1 - Quản trị Tài khoản & Ma trận Phân quyền RBAC Động (Học từ BCDiploma / Parchment)', async () => {
    // 1. Admin dang nhap
    const adminLogin = await fetch('http://localhost:14201/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'admin', password: DEMO_PASSWORD})
    });
    expect(adminLogin.status).toBe(200);
    const adminCookie = extractCookie(adminLogin, 'iss_sid');

    // 2. Admin tao tai khoan Chuyen vien Giao vu moi (giaovu.moi)
    const createRes = await fetch('http://localhost:14201/api/portal/users', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: adminCookie},
      body: JSON.stringify({
        username: 'giaovu.moi',
        fullName: 'Đặng Quốc Khánh',
        email: 'khanhdq@vnu.edu.vn',
        role: 'REGISTRAR',
        title: 'Chuyên viên Phòng Đào tạo',
        password: 'NewStaff@2026'
      })
    });
    expect(createRes.status).toBe(201);

    // 3. Can bo moi dang nhap thanh cong
    const staffLogin = await fetch('http://localhost:14201/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'giaovu.moi', password: 'NewStaff@2026'})
    });
    expect(staffLogin.status).toBe(200);
    const staffCookie = extractCookie(staffLogin, 'iss_sid');

    // 4. Admin khoa tai khoan giaovu.moi -> Phien cua giaovu.moi bi chan ngay voi ma 403 ACCOUNT_LOCKED
    const lockRes = await fetch('http://localhost:14201/api/portal/users/giaovu.moi/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: adminCookie},
      body: '{}'
    });
    expect(lockRes.status).toBe(200);
    expect((await lockRes.json()).user.active).toBe(false);

    const tryLockedLogin = await fetch('http://localhost:14201/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'giaovu.moi', password: 'NewStaff@2026'})
    });
    expect(tryLockedLogin.status).toBe(403);
    expect((await tryLockedLogin.json()).code).toBe('ACCOUNT_LOCKED');

    // 5. Admin mo khoa va cap quyen dong audit.read cho vai tro REGISTRAR tren ma tran RBAC
    await fetch('http://localhost:14201/api/portal/users/giaovu.moi/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: adminCookie},
      body: '{}'
    });

    const rbacUpdate = await fetch('http://localhost:14201/api/portal/rbac/REGISTRAR', {
      method: 'PUT',
      headers: {'Content-Type': 'application/json', Cookie: adminCookie},
      body: JSON.stringify({permissions: ['students.write', 'records.create', 'audit.read']})
    });
    expect(rbacUpdate.status).toBe(200);

    // Dang nhap lai giaovu.moi va kiem tra quyen audit.read da co hieu luc dong
    const staffReLogin = await fetch('http://localhost:14201/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'giaovu.moi', password: 'NewStaff@2026'})
    });
    const newStaffCookie = extractCookie(staffReLogin, 'iss_sid');
    const auditCheck = await fetch('http://localhost:14201/api/portal/audit?limit=5', {
      headers: {Cookie: newStaffCookie}
    });
    expect(auditCheck.status).toBe(200);
    const oldSession = await fetch('http://localhost:14201/api/portal/auth/me', {
      headers: {Cookie: staffCookie}
    });
    expect(oldSession.status).toBe(401);
  });

  it('W9.2 - Nhập danh sách Sinh viên tốt nghiệp theo lô từ tệp CSV & Phê duyệt hàng loạt (Học từ Parchment / OpenCerts)', async () => {
    const regLogin = await fetch('http://localhost:14201/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'chuyenvien', password: DEMO_PASSWORD})
    });
    const regCookie = extractCookie(regLogin, 'iss_sid');

    const csvText = [
      'studentCode,fullName,email,nationalId,dateOfBirth,className,major,degreeName,cohort,status,graduationDate,gpa,classification',
      '23020501,Hoàng Minh Tuấn,23020501@vnu.edu.vn,001205005001,2005-02-11,K68-CNTT1,Công nghệ thông tin,Cử nhân Công nghệ thông tin,K68,GRADUATED,2026-06-30,3.55,Giỏi',
      '23020502,Lương Bích Ngọc,23020502@vnu.edu.vn,001205005002,2005-08-22,K68-KHMT,Khoa học máy tính,Cử nhân Khoa học máy tính,K68,GRADUATED,2026-06-30,3.72,Xuất sắc',
      'BAD_CODE,Sinh Viên Lỗi,bad@vnu.edu.vn,123,2005-01-01,K68,CNTT,Cử nhân,K68,GRADUATED,2026-06-30,3.10,Khá'
    ].join('\n');

    const csvRes = await fetch('http://localhost:14201/api/portal/students/import-csv', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: regCookie},
      body: JSON.stringify({csvText, autoCreateProposals: true, note: 'Đợt xét tốt nghiệp CSV tháng 10/2026'})
    });
    expect(csvRes.status).toBe(201);
    const csvData = await csvRes.json();
    expect(csvData.importedCount).toBe(2);
    expect(csvData.proposalCreatedCount).toBe(2);
    expect(csvData.errors.length).toBe(1);
    expect(csvData.createdRecordIds.length).toBe(2);

    // Truong phong dang nhap va phe duyet theo lo (Batch Approve)
    const appLogin = await fetch('http://localhost:14201/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'truongphong', password: DEMO_PASSWORD})
    });
    const appCookie = extractCookie(appLogin, 'iss_sid');

    const batchRes = await fetch('http://localhost:14201/api/portal/records/batch-approve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: appCookie},
      body: JSON.stringify({
        recordIds: csvData.createdRecordIds,
        note: 'Phê duyệt hàng loạt theo quyết định tốt nghiệp đợt 2'
      })
    });
    expect(batchRes.status).toBe(200);
    const batchData = await batchRes.json();
    expect(batchData.approvedCount).toBe(2);
  });

  it('W9.3 - Đồng bộ Phiên đăng nhập phân tán trên Redis 7 (RedisSessionStore) & Phục hồi sau khi xóa RAM', async () => {
    const loginRes = await fetch('http://localhost:14201/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'admin', password: DEMO_PASSWORD})
    });
    const cookieHeader = extractCookie(loginRes, 'iss_sid');
    const sessionId = extractCookieValue(cookieHeader, 'iss_sid');
    expect(sessionId.length).toBeGreaterThan(16);

    const ttl = await issuer.portal.sessions.redisStore.getTtl('iss_sid', sessionId);
    expect(ttl).toBeGreaterThan(0);
    const other = new SessionManager<{username: string}>('iss_sid');
    const recovered = await other.getAsync({headers: {cookie: cookieHeader}} as any);
    expect(recovered?.user.username).toBe('admin');

    const logout = await fetch('http://localhost:14201/api/portal/auth/logout', {
      method: 'POST', headers: {Cookie: cookieHeader}
    });
    expect(logout.status).toBe(200);
    expect(await other.getAsync({headers: {cookie: cookieHeader}} as any)).toBeNull();

    const shortLived = {...recovered!, createdAt: Date.now() - 5000};
    await other.redisStore.setSession('iss_sid', shortLived, 30);
    const expired = await other.redisStore.loadAndTouch('iss_sid', sessionId, 30_000, 4000);
    expect(expired).toBeNull();
    expect(await other.redisStore.getTtl('iss_sid', sessionId)).toBe(-2);
  });

  it('W9.4 - Bọc mã hóa Khóa Bí mật của Trường bằng Envelope Encryption (AES-256-GCM + scrypt) trong KeyVaultProvider', async () => {
    const savedVault = await issuer.docs.get<any>('keys', issuer.issuerDid);
    expect(savedVault).toBeDefined();
    expect(savedVault.vaultVersion).toBe('1.0');
    expect(savedVault.issuer.type).toBe('EncryptedMultikeyEnvelope');
    expect(savedVault.issuer.cipher).toBe('aes-256-gcm');
    // Tuyet doi KHONG co secretKeyMultibase dang ro trong CSDL
    expect(savedVault.issuer.secretKeyMultibase).toBeUndefined();
    expect(savedVault.approver.secretKeyMultibase).toBeUndefined();

    // Kiem tra unseal thanh cong voi khoa chu dung
    const unsealed = await unsealMultikey(savedVault.issuer);
    expect(unsealed.id).toBe(issuer.issuerKeyPair.id);

    // Kiem tra unseal voi khoa chu sai -> Nem ngoai le KEY_VAULT_DECRYPT_FAILED
    await expect(unsealMultikey(savedVault.issuer, 'wrong-master-kms-key')).rejects.toThrow(/KEY_VAULT_DECRYPT_FAILED/);
  });

  it('W9.5 - Vòng đời Tạm đình chỉ (SUSPEND) và Khôi phục hiệu lực (REINSTATE) văn bằng theo chuẩn Europass EDC / EBSI', async () => {
    // 1. Sinh vien 23020009 dang nhap Vi va nhan van bang rec-deg-23020009
    const stuLogin = await fetch('http://localhost:14200/api/wallet-portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({method: 'sso', identifier: '23020009@vnu.edu.vn', password: DEMO_PASSWORD})
    });
    const walCookie = extractCookie(stuLogin, 'wal_sid');

    const claimRes = await fetch('http://localhost:14200/api/wallet-portal/claim', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: walCookie},
      body: JSON.stringify({recordId: 'rec-deg-23020009'})
    });
    expect(claimRes.status).toBe(200);

    // 2. Truong phong Dao tao TAM DINH CHI (SUSPEND) van bang rec-deg-23020009 de rà soát học vụ
    const appLogin = await fetch('http://localhost:14201/api/portal/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'truongphong', password: DEMO_PASSWORD})
    });
    const appCookie = extractCookie(appLogin, 'iss_sid');

    const suspendRes = await fetch('http://localhost:14201/api/portal/records/rec-deg-23020009/suspend', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: appCookie},
      body: JSON.stringify({reason: 'Tạm đình chỉ để đối chiếu điểm học phần tự chọn'})
    });
    expect(suspendRes.status).toBe(200);
    expect((await suspendRes.json()).record.status).toBe('SUSPENDED');

    const rpLogin = await fetch('http://localhost:14202/api/rp/auth/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'hr.fpt', password: DEMO_PASSWORD})
    });
    const rpCookie = extractCookie(rpLogin, 'rp_sid');
    const issueRequest = async () => {
      const response = await fetch('http://localhost:14202/api/verifier/request', {
        method: 'POST', headers: {'Content-Type': 'application/json', Cookie: rpCookie},
        body: JSON.stringify({credentialType: 'DegreeCredential', claims: ['major']})
      });
      expect(response.status).toBe(201);
      return response.json();
    };
    const preview = async (request: unknown) => {
      const response = await fetch('http://localhost:14200/api/wallet/preview', {
        method: 'POST', headers: {'Content-Type': 'application/json', Cookie: walCookie},
        body: JSON.stringify({request, credentialId: 'rec-deg-23020009'})
      });
      expect(response.status).toBe(200);
      return (await response.json()).consentId;
    };
    const req1Data = await issueRequest();

    const presWhileSuspended = await fetch('http://localhost:14200/api/wallet/present', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: walCookie},
      body: JSON.stringify({
        request: req1Data.request,
        credentialId: 'rec-deg-23020009',
        consent: true,
        consentId: await preview(req1Data.request),
        submit: true
      })
    });
    const presSuspendedData = await presWhileSuspended.json();
    expect(presSuspendedData.submitted.status).toBe(400);
    expect(presSuspendedData.submitted.body.step).toBe('status');

    // 4. Truong phong KHOI PHUC HIEU LUC (REINSTATE) van bang -> Sinh vien trinh bay lai THANH CONG (HTTP 200)
    const reinstateRes = await fetch('http://localhost:14201/api/portal/records/rec-deg-23020009/reinstate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: appCookie},
      body: JSON.stringify({note: 'Đã hoàn tất đối chiếu học vụ, khôi phục hiệu lực'})
    });
    expect(reinstateRes.status).toBe(200);
    expect((await reinstateRes.json()).record.status).toBe('ISSUED');

    const req2Data = await issueRequest();

    const presAfterReinstate = await fetch('http://localhost:14200/api/wallet/present', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: walCookie},
      body: JSON.stringify({
        request: req2Data.request,
        credentialId: 'rec-deg-23020009',
        consent: true,
        consentId: await preview(req2Data.request),
        submit: true
      })
    });
    const presReinstateData = await presAfterReinstate.json();
    expect(presReinstateData.submitted.status).toBe(200);
    expect(presReinstateData.submitted.body.verified).toBe(true);
  });

  it('W9.6 - Chuẩn hóa Cổng Định danh OIDC / VNeID (id_token ký số ES256 & /.well-known/openid-configuration)', async () => {
    const discRes = await fetch('http://localhost:14201/.well-known/openid-configuration');
    expect(discRes.status).toBe(200);
    const disc = await discRes.json();
    expect(disc.id_token_signing_alg_values_supported).toContain('ES256');

    const jwksRes = await fetch('http://localhost:14201/.well-known/jwks.json');
    expect(jwksRes.status).toBe(200);
    const jwks = await jwksRes.json();
    expect(jwks.keys[0].alg).toBe('ES256');

    // Cuu sinh vien K56 dang nhap qua VNeID -> Nhan id_token ES256 chuan OIDC
    const vneidLogin = await fetch('http://localhost:14201/api/student-auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({method: 'vneid', identifier: '001193005566', password: DEMO_PASSWORD})
    });
    expect(vneidLogin.status).toBe(200);
    const loginData = await vneidLogin.json();
    expect(loginData.id_token).toBeDefined();

    // Kiem tra chu ky ES256 cua id_token
    const verifyRes = await fetch('http://localhost:14201/api/student-auth/verify-id-token', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id_token: loginData.id_token})
    });
    expect(verifyRes.status).toBe(200);
    const verified = await verifyRes.json();
    expect(verified.valid).toBe(true);
    expect(verified.claims.acr).toBe('urn:gov:vn:vneid:loa2');
    expect(verified.claims.student_code).toBe('11020345');
  });

  it('W9.7 - Chứng thực Khóa Thiết bị Không Trích xuất được bằng WebCrypto API (extractable: false)', async () => {
    const res = await fetch('http://localhost:14201/api/student-auth/webcrypto-attest', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({challenge: 'nonce-webcrypto-test-2026', audience: 'did:web:fpt.com'})
    });
    expect(res.status).toBe(200);
    const {attestation} = await res.json();
    expect(attestation.extractable).toBe(false);
    expect(attestation.verified).toBe(true);
    expect(attestation.algorithm).toBe('ECDSA-P256-SHA256');
  });

  it('W9.8 - Xuất & Kiểm định Biên bản Chứng nhận Xác minh Mật mã (Cryptographic Verification Receipt - Học từ OpenCerts & Credly)', async () => {
    const rpLogin = await fetch('http://localhost:14202/api/rp/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'hr.fpt', password: DEMO_PASSWORD})
    });
    const rpCookie = extractCookie(rpLogin, 'rp_sid');

    const listRes = await fetch('http://localhost:14202/api/rp/verifications?status=verified', {
      headers: {Cookie: rpCookie}
    });
    const listData = await listRes.json();
    expect(listData.items.length).toBeGreaterThanOrEqual(1);
    const state = listData.items[0].state;

    // 1. Xuat Bien ban Chung nhan Xac minh Mat ma
    const recRes = await fetch(`http://localhost:14202/api/rp/verifications/${state}/receipt`, {
      headers: {Cookie: rpCookie}
    });
    expect(recRes.status).toBe(200);
    const {receipt} = await recRes.json();
    expect(receipt.receiptId).toMatch(/^VR-/);
    expect(receipt.evidenceHash).toMatch(/^urn:sha256:/);
    expect(receipt.cryptographicChecks.step2_issuerEcdsaSd2023).toBe('PASS');

    // 2. Kiem dinh bien ban hop le
    const verifyOk = await fetch('http://localhost:14202/api/rp/receipts/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({receipt})
    });
    expect(verifyOk.status).toBe(200);
    expect((await verifyOk.json()).valid).toBe(true);

    // 3. Thu sua len noi dung bien ban -> Bi phat hien ngay voi ma 400 RECEIPT_TAMPERED
    const tampered = {...receipt, candidate: {...receipt.candidate, studentName: 'Kẻ Giả Mạo'}};
    const verifyBad = await fetch('http://localhost:14202/api/rp/receipts/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({receipt: tampered})
    });
    expect(verifyBad.status).toBe(400);
    expect((await verifyBad.json()).code).toBe('RECEIPT_TAMPERED');
  });

  it('W9.9 - Quản lý Tài khoản Nhân sự HR Động phía Doanh nghiệp', async () => {
    const rpLogin = await fetch('http://localhost:14202/api/rp/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'hr.fpt', password: DEMO_PASSWORD})
    });
    const rpCookie = extractCookie(rpLogin, 'rp_sid');

    const createHr = await fetch('http://localhost:14202/api/rp/users', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Cookie: rpCookie},
      body: JSON.stringify({
        username: 'recruiter2.fpt',
        fullName: 'Trịnh Hoàng Lan',
        email: 'lanth@fpt.com',
        role: 'HR_STAFF',
        password: 'FptRecruiter2@2026'
      })
    });
    expect(createHr.status).toBe(201);

    const newHrLogin = await fetch('http://localhost:14202/api/rp/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'recruiter2.fpt', password: 'FptRecruiter2@2026'})
    });
    expect(newHrLogin.status).toBe(200);
  });
});
