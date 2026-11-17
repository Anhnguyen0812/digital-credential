import {createHash, createHmac, randomUUID, timingSafeEqual} from 'node:crypto';
import type {DocStore} from '../infra/doc-store.js';
import type {VerifierStatusCache} from '../status/status-store.js';
import {hashPassword, verifyPassword, passwordPolicyError} from '../auth/password.js';
import {SessionManager, LoginThrottle, clientIp} from '../auth/session.js';
import {Router, HttpError, created, required, str, RouteCtx} from './router.js';
import {DEMO_PASSWORD, RP_ORGS, RP_USERS, RpRole} from './seed-data.js';

export interface RpSessionUser {
  username: string;
  fullName: string;
  email: string;
  orgId: string;
  orgName: string;
  orgShort: string;
  orgDomain: string;
  role: RpRole;
}

export interface VerificationLogItem {
  state: string;
  at: string;
  orgId: string;
  verifierName: string;
  requestedBy: string;
  credentialType: string;
  requestedClaims: string[];
  verified: boolean;
  studentName?: string;
  disclosedClaims?: Record<string, any>;
  timings: Record<string, number>;
  attackType?: string;
  step?: string;
  reason?: string;
  httpStatus: number;
  legacyDocument?: string;
}

const RP_PERMISSIONS: Record<RpRole, string[]> = {
  HR_MANAGER: ['request.create', 'history.read', 'templates.manage', 'config.manage'],
  HR_STAFF: ['request.create', 'history.read']
};

const DEFAULT_TEMPLATES = [
  {
    id: 'tpl-swe',
    name: 'Tuyển dụng Kỹ sư Phần mềm (Ẩn GPA & MSSV)',
    description: 'Chỉ xác minh đã tốt nghiệp, tên văn bằng và chuyên ngành theo nguyên tắc tối thiểu hóa dữ liệu.',
    credentialType: 'DegreeCredential',
    claims: ['major', 'degreeName', 'graduationDate']
  },
  {
    id: 'tpl-rd',
    name: 'Tuyển dụng R&D / Học bổng Kỹ sư Tài năng',
    description: 'Yêu cầu tiết lộ đầy đủ Chuyên ngành, Xếp loại bằng và Điểm trung bình tích lũy (GPA).',
    credentialType: 'DegreeCredential',
    claims: ['major', 'degreeName', 'graduationDate', 'classification', 'gpa']
  },
  {
    id: 'tpl-sec',
    name: 'Thẩm định Chứng chỉ An toàn Thông tin (INT3306)',
    description: 'Kiểm tra chứng chỉ khóa học ngắn hạn, kỹ năng đạt được và điểm số học phần.',
    credentialType: 'CourseCertificateCredential',
    claims: ['courseCode', 'courseHours', 'grade', 'skills']
  },
  {
    id: 'tpl-legacy',
    name: 'Xác minh Văn bằng Cấp lại từ Sổ gốc (Kèm Watermark)',
    description: 'Dành cho cựu sinh viên tốt nghiệp giai đoạn trước chuyển đổi số, có đối chiếu bản scan sổ gốc.',
    credentialType: 'DegreeCredential',
    claims: ['major', 'degreeName', 'graduationDate', 'classification']
  }
];

export async function createVerifierPortal(opts: {
  docs: DocStore;
  statusCache: VerifierStatusCache;
  suspensionCache: VerifierStatusCache;
}) {
  const {docs, statusCache} = opts;
  const sessions = new SessionManager<RpSessionUser>('rp_sid');
  const throttle = new LoginThrottle();

  if (await docs.count('rp_users') === 0) {
    await Promise.all(RP_USERS.map(async u => {
      const org = RP_ORGS[u.orgId];
      await docs.put('rp_users', u.username, {
        ...u,
        orgName: org.name,
        orgShort: org.shortName,
        orgDomain: org.domain,
        active: true,
        passwordHash: await hashPassword(DEMO_PASSWORD),
        createdAt: new Date().toISOString()
      });
    }));
  }

  if (await docs.count('templates') === 0) {
    for (const t of DEFAULT_TEMPLATES) {
      await docs.put('templates', t.id, {...t, createdBy: 'system', createdAt: new Date().toISOString()});
    }
  }

  async function auth(ctx: Pick<RouteCtx, "req">): Promise<RpSessionUser> {
    const s = await sessions.getAsync(ctx.req);
    if (!s) throw new HttpError(401, 'Vui lòng đăng nhập Cổng Tuyển dụng', 'UNAUTHENTICATED');
    const current = await docs.get('rp_users', s.user.username);
    if(!current || current.active === false || current.orgId !== s.user.orgId) throw new HttpError(403, 'Tài khoản không còn quyền truy cập');
    return {...s.user, role: current.role};
  }

  async function need(ctx: Pick<RouteCtx, 'req'>, perm: string): Promise<RpSessionUser> {
    const u = await auth(ctx);
    if (!RP_PERMISSIONS[u.role].includes(perm)) {
      throw new HttpError(403, `Tài khoản "${u.role === 'HR_STAFF' ? 'Chuyên viên Tuyển dụng' : 'Quản lý Nhân sự'}" không có quyền thực hiện thao tác này`, 'RBAC_FORBIDDEN');
    }
    return u;
  }

  const router = new Router();

  router.post('/api/rp/auth/login', async ctx => {
    required(ctx.body, ['username', 'password']);
    const username = str(ctx.body.username, 64).toLowerCase();
    const key = `rp|${clientIp(ctx.req)}|${username}`;
    const wait = throttle.check(key);
    if (wait) throw new HttpError(429, `Đăng nhập sai quá nhiều lần. Thử lại sau ${wait} giây`);
    const u = await docs.get('rp_users', username);
    if (!u || !(await verifyPassword(String(ctx.body.password), u.passwordHash))) {
      throttle.fail(key);
      throw new HttpError(401, 'Tài khoản hoặc mật khẩu không đúng');
    }
    if (u.active === false) {
      throw new HttpError(403, 'Tài khoản nhân sự đã bị khóa bởi Quản lý Tuyển dụng', 'ACCOUNT_LOCKED');
    }
    throttle.success(key);
    const user: RpSessionUser = {
      username: u.username,
      fullName: u.fullName,
      email: u.email,
      orgId: u.orgId,
      orgName: u.orgName,
      orgShort: u.orgShort,
      orgDomain: u.orgDomain,
      role: u.role
    };
    await sessions.create(user, ctx.req, ctx.res);
    return {user, permissions: RP_PERMISSIONS[user.role]};
  });

  router.post('/api/rp/auth/logout', async ctx => {
    await sessions.destroy(ctx.req, ctx.res);
    return {ok: true};
  });

  router.get('/api/rp/auth/me', async ctx => {
    const user = await auth(ctx);
    return {
      user,
      permissions: RP_PERMISSIONS[user.role],
      cacheMode: statusCache.getMode(),
      cacheCounters: statusCache.counters
    };
  });

  router.get('/api/rp/dashboard', async ctx => {
    const user = await need(ctx, 'history.read');
    const [allVerifications, allTemplates] = await Promise.all([
      docs.list<VerificationLogItem>('verifications'),
      docs.list('templates')
    ]);
    const verifications = allVerifications.filter(item => item.orgId === user.orgId);
    const templates = allTemplates.filter(item => item.createdBy === 'system' || item.orgId === user.orgId);
    verifications.sort((a, b) => b.at.localeCompare(a.at));
    const verified = verifications.filter(v => v.verified);
    const failed = verifications.filter(v => !v.verified);
    const avgLatencyMs = verified.length
      ? verified.reduce((acc, v) => acc + ((v.timings?.redisMs || 0) + (v.timings?.cryptoMs || 0) + (v.timings?.statusMs || 0)), 0) / verified.length
      : 0;
    const byAttack: Record<string, number> = {};
    for (const f of failed) {
      const k = f.attackType || 'UNKNOWN';
      byAttack[k] = (byAttack[k] || 0) + 1;
    }
    return {
      stats: {
        total: verifications.length,
        verified: verified.length,
        blocked: failed.length,
        avgLatencyMs: Number(avgLatencyMs.toFixed(2)),
        byAttack
      },
      cache: {
        mode: statusCache.getMode(),
        ...statusCache.counters
      },
      templates,
      recent: verifications.slice(0, 12)
    };
  });

  router.get('/api/rp/templates', async ctx => {
    const user = await auth(ctx);
    return {items: (await docs.list('templates')).filter(item => item.createdBy === 'system' || item.orgId === user.orgId)};
  });

  router.post('/api/rp/templates', async ctx => {
    const u = await need(ctx, 'templates.manage');
    required(ctx.body, ['name', 'credentialType']);
    const id = 'tpl-' + randomUUID().slice(0, 8);
    const tpl = {
      id,
      name: str(ctx.body.name, 120),
      description: str(ctx.body.description, 300),
      credentialType: ctx.body.credentialType === 'CourseCertificateCredential' ? 'CourseCertificateCredential' : 'DegreeCredential',
      claims: Array.isArray(ctx.body.claims) ? ctx.body.claims.map((x: any) => String(x)) : [],
      createdBy: u.username,
      orgId: u.orgId,
      createdAt: new Date().toISOString()
    };
    await docs.put('templates', id, tpl);
    return created({template: tpl});
  });

  router.post('/api/rp/templates/:id/delete', async ctx => {
    const u = await need(ctx, 'templates.manage');
    const item = await docs.get('templates', ctx.params.id);
    if(!item || item.orgId !== u.orgId) throw new HttpError(404, 'Không tìm thấy mẫu');
    await docs.remove('templates', ctx.params.id);
    return {ok: true};
  });

  router.get('/api/rp/verifications', async ctx => {
    const u = await need(ctx, 'history.read');
    const filter = ctx.url.searchParams.get('status');
    const q = str(ctx.url.searchParams.get('q')).toLowerCase();
    const list = (await docs.list<VerificationLogItem>('verifications'))
      .filter(v => {
        if(v.orgId !== u.orgId) return false;
        if (filter === 'verified' && !v.verified) return false;
        if (filter === 'blocked' && v.verified) return false;
        if (q && !`${v.studentName || ''} ${v.verifierName || ''} ${v.credentialType} ${v.attackType || ''} ${v.reason || ''}`.toLowerCase().includes(q)) return false;
        return true;
      })
      .sort((a, b) => b.at.localeCompare(a.at));
    return {items: list};
  });

  router.get('/api/rp/verifications/:state', async ctx => {
    const u = await need(ctx, 'history.read');
    const item = await docs.get<VerificationLogItem>('verifications', ctx.params.state);
    if(!item || item.orgId !== u.orgId) throw new HttpError(404, 'Không tìm thấy bản ghi xác minh');
    return {item};
  });

  // W9-06: Xuat Bien ban Chung nhan Xac minh Mat ma (Cryptographic Verification Receipt - Hoc tu OpenCerts & Credly)
  const receiptSecret = () => process.env.RECEIPT_SECRET || 'rp-verification-receipt-secret-2026';

  function signReceiptPayload(payload: Record<string, any>): string {
    const canonical = JSON.stringify(payload);
    return createHmac('sha256', receiptSecret()).update(canonical).digest('base64url');
  }

  router.get('/api/rp/verifications/:state/receipt', async ctx => {
    const u = await auth(ctx);
    const item = await docs.get<VerificationLogItem>('verifications', ctx.params.state);
    if(!item || item.orgId !== u.orgId) throw new HttpError(404, 'Không tìm thấy bản ghi xác minh');
    if (!item.verified) throw new HttpError(400, 'Chỉ xuất được biên bản chứng nhận cho các phiên xác minh HỢP LỆ (VERIFIED)');

    const evidencePayload = {
      state: item.state,
      verifiedAt: item.at,
      orgId: item.orgId,
      verifierName: item.verifierName,
      credentialType: item.credentialType,
      studentName: item.studentName,
      disclosedClaims: item.disclosedClaims || {}
    };
    const evidenceHash = 'urn:sha256:' + createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex');

    const receiptBody = {
      receiptVersion: '1.0',
      receiptId: `VR-${item.state.slice(0, 8).toUpperCase()}`,
      state: item.state,
      verifiedAt: item.at,
      exportedAt: new Date().toISOString(),
      exportedBy: u.username,
      organization: {
        orgId: item.orgId || u.orgId,
        orgName: item.verifierName || u.orgName,
        orgDomain: u.orgDomain
      },
      credentialType: item.credentialType,
      candidate: {
        studentName: item.studentName,
        disclosedClaims: item.disclosedClaims || {},
        requestedClaims: item.requestedClaims || []
      },
      privacyGuarantee: 'Selective Disclosure (W3C ecdsa-sd-2023): Các thuộc tính không nằm trong yêu cầu DCQL đã được ẩn mật mã.',
      cryptographicChecks: {
        step1_redisNonceGuard: 'PASS',
        step2_issuerEcdsaSd2023: 'PASS',
        step3_holderBindingRdfc2019: 'PASS',
        step4_bitstringStatusList: 'PASS'
      },
      timings: item.timings,
      evidenceHash
    };
    const signature = signReceiptPayload(receiptBody);
    return {receipt: {...receiptBody, signature}};
  });

  router.post('/api/rp/receipts/verify', async ctx => {
    required(ctx.body, ['receipt']);
    const {signature, ...rest} = ctx.body.receipt || {};
    if (!signature) throw new HttpError(400, 'Thiếu chữ ký biên bản (signature)');
    const expected = Buffer.from(signReceiptPayload(rest), 'utf8');
    const given = Buffer.from(String(signature), 'utf8');
    const valid = expected.length === given.length && timingSafeEqual(expected, given);
    if (!valid) throw new HttpError(400, 'Biên bản chứng nhận xác minh đã bị sửa đổi hoặc chữ ký không hợp lệ', 'RECEIPT_TAMPERED');
    return {valid: true, receiptId: rest.receiptId, evidenceHash: rest.evidenceHash, organization: rest.organization};
  });

  // W9-01 (Phia Doanh nghiep): Quan ly tai khoan Nhan su HR dong
  router.get('/api/rp/users', async ctx => {
    const u = await need(ctx, 'config.manage');
    const all = await docs.list<any>('rp_users');
    return {
      items: all
        .filter(x => x.orgId === u.orgId)
        .map(({passwordHash, ...rest}) => rest)
    };
  });

  router.post('/api/rp/users', async ctx => {
    const u = await need(ctx, 'config.manage');
    required(ctx.body, ['username', 'fullName', 'email', 'role', 'password']);
    const username = str(ctx.body.username, 32).toLowerCase();
    if (await docs.get('rp_users', username)) throw new HttpError(409, 'Tài khoản nhân sự đã tồn tại');
    const pe = passwordPolicyError(ctx.body.password);
    if (pe) throw new HttpError(400, pe);
    const role: RpRole = ctx.body.role === 'HR_MANAGER' ? 'HR_MANAGER' : 'HR_STAFF';
    const newUser = {
      username,
      fullName: str(ctx.body.fullName, 120),
      email: str(ctx.body.email, 120),
      orgId: u.orgId,
      orgName: u.orgName,
      orgShort: u.orgShort,
      orgDomain: u.orgDomain,
      role,
      active: true,
      passwordHash: await hashPassword(ctx.body.password),
      createdAt: new Date().toISOString()
    };
    await docs.put('rp_users', username, newUser);
    const {passwordHash, ...pub} = newUser;
    return created({user: pub});
  });

  async function recordVerification(item: VerificationLogItem) {
    await docs.put('verifications', item.state, item);
  }

  return {router, sessions, recordVerification, auth, need};
}
