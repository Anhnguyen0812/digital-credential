import {randomBytes, randomUUID} from 'node:crypto';
import {verifyCredentialProof} from '../crypto/credential-proof.js';
import {issueSelectiveDisclosureVc} from '../crypto/holder-binding.js';
import {computeDocumentDigest, signLegacyProvenance} from '../crypto/provenance-signer.js';
import {buildUnsignedDegreeVc, DEGREE_MANDATORY_POINTERS, LEGACY_DEGREE_MANDATORY_POINTERS} from '../profiles/degree-profile.js';
import {buildUnsignedCourseVc, COURSE_MANDATORY_POINTERS} from '../profiles/course-profile.js';
import type {IssuerStatusRegistry} from '../status/status-store.js';
import type {AuditStore} from '../infra/postgres-store.js';
import type {DocStore} from '../infra/doc-store.js';
import {hashPassword, verifyPassword, passwordPolicyError} from '../auth/password.js';
import {SessionManager, LoginThrottle, signToken, verifyToken, clientIp} from '../auth/session.js';
import {OidcIdentityProvider, createWebCryptoNonExtractableProof} from '../auth/oidc-provider.js';
import {Router, HttpError, created, required, str, RouteCtx} from './router.js';
import {DEMO_PASSWORD, ISSUER_USERS, STUDENTS, COURSE_CATALOG, IssuerRole, StudentProfile} from './seed-data.js';

export interface IssuerPortalDeps {
  docs: DocStore;
  audit: AuditStore;
  statusRegistry: IssuerStatusRegistry;
  suspensionRegistry: IssuerStatusRegistry;
  allocateStatusIndex: () => Promise<number>;
  issuerKeyPair: any;
  approverKeyPair: any;
  documentLoader: any;
  issuerDid: string;
  statusUrl: string;
  issuerUrl: string;
  sampleScan: () => Buffer;
  registerScan: (digest: string, scan: Buffer) => void;
  oidcProvider?: OidcIdentityProvider;
}

interface StaffUser { sessionVersion?: string; username: string; fullName: string; email: string; role: IssuerRole; title: string }

type RecordKind = 'degree' | 'course' | 'legacy_degree';
type RecordStatus = 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'CANCELLED' | 'ISSUED' | 'SUSPENDED' | 'REVOKED';

export interface CredentialRecord {
  id: string;
  kind: RecordKind;
  status: RecordStatus;
  studentCode: string;
  studentName: string;
  title: string;
  subject: Record<string, any>;
  legacy?: {originalIssueDate: string; registryBookNumber: string; degreeSerial: string; digest: string; scanBytes: number; uploaded: boolean};
  provenance?: any;
  reissueOf?: string;
  reissuedBy?: string;
  note?: string;
  createdBy: string;
  createdAt: string;
  approvedBy?: string; approvedAt?: string;
  rejectedBy?: string; rejectReason?: string;
  issuedAt?: string; holderDid?: string; statusListIndex?: number; credential?: any;
  suspendedBy?: string; suspendedAt?: string; suspendReason?: string;
  revokedBy?: string; revokedAt?: string; revokeReason?: string;
  history: {at: string; actor: string; action: string; note?: string}[];
}

export const ISSUER_PERMISSIONS: Record<IssuerRole, string[]> = {
  ADMIN: ['students.write', 'audit.read', 'users.manage'],
  REGISTRAR: ['students.write', 'records.create'],
  APPROVER: ['records.approve', 'records.revoke', 'audit.read']
};

const ROLE_LABEL: Record<IssuerRole, string> = {ADMIN: 'Quản trị hệ thống', REGISTRAR: 'Chuyên viên Đào tạo', APPROVER: 'Lãnh đạo phê duyệt'};
const ACTIVE: RecordStatus[] = ['PENDING_APPROVAL', 'APPROVED', 'ISSUED', 'SUSPENDED'];

const now = () => new Date().toISOString();
const pubUser = (u: any) => { const {passwordHash, ...rest} = u; return rest; };
const pubStudent = (s: any) => { const {passwordHash, ...rest} = s; return rest; };
const summary = (r: CredentialRecord) => { const {credential, ...rest} = r; return {...rest, hasCredential: !!credential}; };

export async function createIssuerPortal(d: IssuerPortalDeps) {
  const {docs, audit} = d;
  const sessions = new SessionManager<StaffUser>('iss_sid');
  const throttle = new LoginThrottle();
  const nonces = new Map<string, {studentCode: string; exp: number}>();

  // ---------- Seed du lieu demo & Ma tran RBAC dong (chi khi CSDL trong) ----------
  if(await docs.count('rbac_roles') === 0) {
    for(const r of ['ADMIN', 'REGISTRAR', 'APPROVER'] as IssuerRole[]) {
      await docs.put('rbac_roles', r, {
        role: r,
        label: ROLE_LABEL[r],
        permissions: [...ISSUER_PERMISSIONS[r]],
        updatedAt: now()
      });
    }
  }
  if(await docs.count('users') === 0) {
    await Promise.all(ISSUER_USERS.map(async u => docs.put('users', u.username, {
      ...u, active: true, passwordHash: await hashPassword(DEMO_PASSWORD), createdAt: now()
    })));
  }
  if(await docs.count('students') === 0) {
    await Promise.all(STUDENTS.map(async s => docs.put('students', s.studentCode, {
      ...s, passwordHash: await hashPassword(DEMO_PASSWORD), createdAt: now()
    })));
  }
  if(await docs.count('records') === 0) {
    const s1 = STUDENTS[0]; // 23020009 Nguyen Phi Anh
    const s2 = STUDENTS[1]; // 23020114 Tran Minh Khoi
    const sLegacy = STUDENTS[6]; // 11020345 Pham Thu Trang (K56 Alumni)
    const sampleBytes = d.sampleScan();
    const sampleDigest = computeDocumentDigest(sampleBytes);
    d.registerScan(sampleDigest, sampleBytes);

    const seedRecords: CredentialRecord[] = [
      {
        id: 'rec-deg-23020009',
        kind: 'degree',
        status: 'APPROVED',
        studentCode: s1.studentCode,
        studentName: s1.fullName,
        title: s1.degreeName,
        subject: {
          studentName: s1.fullName, studentCode: s1.studentCode, major: s1.major,
          degreeName: s1.degreeName, graduationDate: s1.graduationDate, graduated: true,
          gpa: s1.gpa, classification: s1.classification
        },
        note: 'Đợt xét tốt nghiệp chính quy năm 2026',
        createdBy: 'chuyenvien',
        createdAt: new Date(Date.now() - 3600_000 * 6).toISOString(),
        approvedBy: 'truongphong',
        approvedAt: new Date(Date.now() - 3600_000 * 4).toISOString(),
        history: [
          {at: new Date(Date.now() - 3600_000 * 6).toISOString(), actor: 'chuyenvien', action: 'CREATE', note: 'Đợt xét tốt nghiệp chính quy năm 2026'},
          {at: new Date(Date.now() - 3600_000 * 4).toISOString(), actor: 'truongphong', action: 'APPROVE', note: 'Đã đối chiếu quyết định công nhận tốt nghiệp'}
        ]
      },
      {
        id: 'rec-crs-23020009',
        kind: 'course',
        status: 'APPROVED',
        studentCode: s1.studentCode,
        studentName: s1.fullName,
        title: 'An toàn và Bảo mật Hệ thống Thông tin (INT3306)',
        subject: {
          studentName: s1.fullName, courseCode: 'INT3306',
          courseName: 'An toàn và Bảo mật Hệ thống Thông tin', courseHours: 45,
          completionDate: '2026-01-15', grade: 'A+',
          skills: ['W3C Verifiable Credentials', 'Applied Cryptography', 'Zero Trust'],
          certificateValid: true
        },
        note: 'Hoàn thành xuất sắc học phần chuyên đề',
        createdBy: 'chuyenvien',
        createdAt: new Date(Date.now() - 3600_000 * 12).toISOString(),
        approvedBy: 'truongphong',
        approvedAt: new Date(Date.now() - 3600_000 * 10).toISOString(),
        history: [
          {at: new Date(Date.now() - 3600_000 * 12).toISOString(), actor: 'chuyenvien', action: 'CREATE'},
          {at: new Date(Date.now() - 3600_000 * 10).toISOString(), actor: 'truongphong', action: 'APPROVE'}
        ]
      },
      {
        id: 'rec-deg-23020114',
        kind: 'degree',
        status: 'PENDING_APPROVAL',
        studentCode: s2.studentCode,
        studentName: s2.fullName,
        title: s2.degreeName,
        subject: {
          studentName: s2.fullName, studentCode: s2.studentCode, major: s2.major,
          degreeName: s2.degreeName, graduationDate: s2.graduationDate, graduated: true,
          gpa: s2.gpa, classification: s2.classification
        },
        note: 'Chờ lãnh đạo Phòng Đào tạo ký duyệt phát hành',
        createdBy: 'chuyenvien',
        createdAt: new Date(Date.now() - 3600_000 * 2).toISOString(),
        history: [
          {at: new Date(Date.now() - 3600_000 * 2).toISOString(), actor: 'chuyenvien', action: 'CREATE', note: 'Chờ lãnh đạo Phòng Đào tạo ký duyệt phát hành'}
        ]
      },
      {
        id: 'rec-leg-11020345',
        kind: 'legacy_degree',
        status: 'PENDING_APPROVAL',
        studentCode: sLegacy.studentCode,
        studentName: sLegacy.fullName,
        title: `${sLegacy.degreeName} (số hóa từ sổ gốc)`,
        subject: {
          studentName: sLegacy.fullName, studentCode: sLegacy.studentCode, major: sLegacy.major,
          degreeName: sLegacy.degreeName, graduationDate: sLegacy.graduationDate, graduated: true,
          gpa: sLegacy.gpa, classification: sLegacy.classification
        },
        legacy: {
          originalIssueDate: '2015-06-25',
          registryBookNumber: 'BK-2015/0842',
          degreeSerial: 'B15-004921',
          digest: sampleDigest,
          scanBytes: sampleBytes.length,
          uploaded: false
        },
        note: 'Hồ sơ số hóa sổ gốc khóa K56 — chờ Trưởng phòng ký số Multikey',
        createdBy: 'chuyenvien',
        createdAt: new Date(Date.now() - 3600_000 * 1).toISOString(),
        history: [
          {at: new Date(Date.now() - 3600_000 * 1).toISOString(), actor: 'chuyenvien', action: 'LEGACY_INGEST', note: 'Đối chiếu sổ BK-2015/0842, số hiệu B15-004921'}
        ]
      }
    ];
    for (const r of seedRecords) await docs.put('records', r.id, r);
  }

  const log = (event: string, actor: string, detail: Record<string, unknown> = {}) => audit.audit(event, {actor, ...detail});

  async function rolePermissions(role: IssuerRole): Promise<string[]> {
    const dyn = await docs.get<{permissions: string[]}>('rbac_roles', role);
    return dyn?.permissions ?? ISSUER_PERMISSIONS[role] ?? [];
  }

  async function authAsync(ctx: Pick<RouteCtx, 'req'>): Promise<StaffUser> {
    const s = await sessions.getAsync(ctx.req);
    if(!s) throw new HttpError(401, 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại', 'UNAUTHENTICATED');
    const u = await docs.get('users', s.user.username);
    if(!u?.active) throw new HttpError(403, 'Tài khoản đã bị khóa hoặc không còn tồn tại', 'ACCOUNT_LOCKED');
    if(u.sessionVersion !== s.user.sessionVersion) throw new HttpError(401, 'Vui lòng đăng nhập lại', 'UNAUTHENTICATED');
    return {...s.user, role: u.role, title: u.title};
  }

  async function need(ctx: RouteCtx, perm: string): Promise<StaffUser> {
    const u = await authAsync(ctx);
    const perms = await rolePermissions(u.role);
    if(!perms.includes(perm)) {
      await log('ACCESS_DENIED', u.username, {role: u.role, permission: perm, path: ctx.url.pathname});
      throw new HttpError(403, `Vai trò "${ROLE_LABEL[u.role]}" không có quyền thực hiện thao tác này`, 'RBAC_FORBIDDEN');
    }
    return u;
  }
  async function getRecord(id: string): Promise<CredentialRecord> {
    const r = await docs.get<CredentialRecord>('records', id);
    if(!r) throw new HttpError(404, 'Không tìm thấy hồ sơ cấp văn bằng');
    return r;
  }
  async function getStudent(code: string): Promise<StudentProfile & {passwordHash?: string}> {
    const s = await docs.get('students', code);
    if(!s) throw new HttpError(404, `Không tìm thấy sinh viên ${code}`);
    return s;
  }
  const push = (r: CredentialRecord, actor: string, action: string, note?: string) => r.history.push({at: now(), actor, action, note});

  // ---------- Ky phat hanh VC (goi khi sinh vien nhan van bang vao vi, sau khi da duoc phe duyet) ----------
  async function issueVc(r: CredentialRecord, holderDid: string) {
    const index = await d.allocateStatusIndex();
    if(r.kind === 'course') {
      const from = new Date();
      const until = new Date(from); until.setFullYear(until.getFullYear() + 2);
      const unsigned = buildUnsignedCourseVc({
        holderDid, statusListIndex: index, statusListUrl: d.statusUrl, suspensionListUrl: d.suspensionRegistry.listUrl, issuerDid: d.issuerDid, subject: r.subject,
        validFrom: from.toISOString().slice(0, 19) + 'Z', validUntil: until.toISOString().slice(0, 19) + 'Z'
      });
      return {index, credential: await issueSelectiveDisclosureVc({unsignedCredential: unsigned, issuerKeyPair: d.issuerKeyPair, mandatoryPointers: COURSE_MANDATORY_POINTERS, documentLoader: d.documentLoader})};
    }
    const unsigned = buildUnsignedDegreeVc({
      holderDid, statusListIndex: index, statusListUrl: d.statusUrl, suspensionListUrl: d.suspensionRegistry.listUrl, issuerDid: d.issuerDid,
      subject: r.subject as any, legacyProvenance: r.kind === 'legacy_degree' ? r.provenance : undefined
    });
    const pointers = r.kind === 'legacy_degree' ? LEGACY_DEGREE_MANDATORY_POINTERS : DEGREE_MANDATORY_POINTERS;
    return {index, credential: await issueSelectiveDisclosureVc({unsignedCredential: unsigned, issuerKeyPair: d.issuerKeyPair, mandatoryPointers: pointers, documentLoader: d.documentLoader})};
  }

  async function revokeRecord(r: CredentialRecord, actor: string, reason: string) {
    r.status = 'REVOKED'; r.revokedBy = actor; r.revokedAt = now(); r.revokeReason = reason;
    push(r, actor, 'REVOKE', reason);
    await docs.put('records', r.id, r);
    await log('RECORD_REVOKE', actor, {recordId: r.id, studentCode: r.studentCode, statusListIndex: r.statusListIndex, reason});
  }

  function degreeSubject(s: StudentProfile) {
    return {
      studentName: s.fullName, studentCode: s.studentCode, major: s.major, degreeName: s.degreeName,
      graduationDate: s.graduationDate, graduated: true, gpa: s.gpa, classification: s.classification
    };
  }

  const router = new Router();

  // ======================= XAC THUC CAN BO =======================
  router.post('/api/portal/auth/login', async ctx => {
    required(ctx.body, ['username', 'password']);
    const username = str(ctx.body.username, 64).toLowerCase();
    const key = `${clientIp(ctx.req)}|${username}`;
    const wait = throttle.check(key);
    if(wait) throw new HttpError(429, `Đăng nhập sai quá nhiều lần. Thử lại sau ${wait} giây`);
    const u = await docs.get('users', username);
    if(!u || !(await verifyPassword(String(ctx.body.password), u.passwordHash))) {
      throttle.fail(key);
      await log('LOGIN_FAILED', username, {ip: clientIp(ctx.req)});
      throw new HttpError(401, 'Tên đăng nhập hoặc mật khẩu không đúng');
    }
    if(!u.active) throw new HttpError(403, 'Tài khoản đã bị khóa. Liên hệ quản trị hệ thống', 'ACCOUNT_LOCKED');
    throttle.success(key);
    const user: StaffUser = {username: u.username, fullName: u.fullName, email: u.email, role: u.role, title: u.title};
    user.sessionVersion = u.sessionVersion;
    await sessions.create(user, ctx.req, ctx.res);
    u.lastLoginAt = now();
    await docs.put('users', u.username, u);
    await log('LOGIN', u.username, {role: u.role});
    return {user, permissions: await rolePermissions(user.role)};
  });

  router.post('/api/portal/auth/logout', async ctx => {
    const s = await sessions.getAsync(ctx.req);
    await sessions.destroy(ctx.req, ctx.res);
    if(s) await log('LOGOUT', s.user.username);
    return {ok: true};
  });

  router.get('/api/portal/auth/me', async ctx => {
    const user = await authAsync(ctx);
    return {user, permissions: await rolePermissions(user.role), issuerDid: d.issuerDid};
  });

  router.post('/api/portal/auth/change-password', async ctx => {
    const user = await authAsync(ctx);
    required(ctx.body, ['current', 'next']);
    const u = await docs.get('users', user.username);
    if(!(await verifyPassword(String(ctx.body.current), u.passwordHash))) throw new HttpError(400, 'Mật khẩu hiện tại không đúng');
    const err = passwordPolicyError(ctx.body.next);
    if(err) throw new HttpError(400, err);
    u.passwordHash = await hashPassword(ctx.body.next);
    u.sessionVersion = randomUUID();
    await docs.put('users', u.username, u);
    await log('PASSWORD_CHANGE', user.username);
    return {ok: true};
  });

  // ======================= TONG QUAN =======================
  router.get('/api/portal/dashboard', async ctx => {
    const user = await authAsync(ctx);
    const [records, students, recent] = await Promise.all([
      docs.list<CredentialRecord>('records'), docs.list<StudentProfile>('students'), audit.listAudit(8)
    ]);
    const byStatus: Record<string, number> = {};
    for(const r of records) byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
    const days: {date: string; issued: number; requested: number}[] = [];
    for(let i = 13; i >= 0; i--) {
      const dt = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
      days.push({
        date: dt,
        issued: records.filter(r => r.issuedAt?.startsWith(dt)).length,
        requested: records.filter(r => r.createdAt.startsWith(dt)).length
      });
    }
    const todo = user.role === 'APPROVER'
      ? records.filter(r => r.status === 'PENDING_APPROVAL')
      : user.role === 'REGISTRAR'
        ? records.filter(r => r.createdBy === user.username && (r.status === 'REJECTED' || r.status === 'PENDING_APPROVAL'))
        : [];
    return {
      students: {total: students.length, graduated: students.filter(s => s.status === 'GRADUATED').length, studying: students.filter(s => s.status === 'STUDYING').length},
      records: {total: records.length, byStatus},
      statusList: {allocated: d.statusRegistry.allocatedCount, capacity: d.statusRegistry.list.length, revoked: byStatus.REVOKED ?? 0},
      series: days,
      todo: todo.slice(0, 6).map(summary),
      recent
    };
  });

  // ======================= SINH VIEN =======================
  router.get('/api/portal/students', async ctx => {
    await authAsync(ctx);
    const q = str(ctx.url.searchParams.get('q')).toLowerCase();
    const status = ctx.url.searchParams.get('status');
    const [students, records] = await Promise.all([docs.list('students'), docs.list<CredentialRecord>('records')]);
    return {
      items: students
        .filter(s => (!status || s.status === status) && (!q || `${s.studentCode} ${s.fullName} ${s.email} ${s.className}`.toLowerCase().includes(q)))
        .sort((a, b) => a.studentCode.localeCompare(b.studentCode))
        .map(s => ({...pubStudent(s), credentialCount: records.filter(r => r.studentCode === s.studentCode && r.status === 'ISSUED').length}))
    };
  });

  router.get('/api/portal/students/:code', async ctx => {
    await authAsync(ctx);
    const s = await getStudent(ctx.params.code);
    const records = (await docs.list<CredentialRecord>('records')).filter(r => r.studentCode === s.studentCode)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(summary);
    return {student: pubStudent(s), records};
  });

  function validateStudent(b: any, partial = false) {
    if(!partial) required(b, ['studentCode', 'fullName', 'email', 'nationalId', 'major', 'degreeName']);
    if(b.studentCode !== undefined && !/^\d{8}$/.test(String(b.studentCode))) throw new HttpError(400, 'Mã sinh viên phải gồm 8 chữ số');
    if(b.nationalId !== undefined && !/^\d{12}$/.test(String(b.nationalId))) throw new HttpError(400, 'Số CCCD phải gồm 12 chữ số');
    if(b.email !== undefined && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(b.email))) throw new HttpError(400, 'Email không hợp lệ');
    if(b.gpa !== undefined && b.gpa !== '' && !(Number(b.gpa) >= 0 && Number(b.gpa) <= 4)) throw new HttpError(400, 'GPA phải nằm trong khoảng 0 – 4');
    if(b.status !== undefined && !['STUDYING', 'GRADUATED'].includes(b.status)) throw new HttpError(400, 'Trạng thái không hợp lệ');
  }
  const EDITABLE = ['fullName', 'email', 'emailActive', 'nationalId', 'dateOfBirth', 'className', 'major', 'degreeName', 'cohort', 'status', 'graduationDate', 'gpa', 'classification'];

  router.post('/api/portal/students', async ctx => {
    const user = await need(ctx, 'students.write');
    validateStudent(ctx.body);
    const code = String(ctx.body.studentCode);
    if(await docs.get('students', code)) throw new HttpError(409, `Mã sinh viên ${code} đã tồn tại`);
    const s: any = {studentCode: code, emailActive: true, status: 'STUDYING', createdAt: now(), passwordHash: await hashPassword(DEMO_PASSWORD)};
    for(const k of EDITABLE) if(ctx.body[k] !== undefined) s[k] = typeof ctx.body[k] === 'string' ? str(ctx.body[k]) : ctx.body[k];
    if(s.gpa !== undefined) s.gpa = Number(s.gpa).toFixed(2);
    await docs.put('students', code, s);
    await log('STUDENT_CREATE', user.username, {studentCode: code});
    return created({student: pubStudent(s)});
  });

  router.put('/api/portal/students/:code', async ctx => {
    const user = await need(ctx, 'students.write');
    const s: any = await getStudent(ctx.params.code);
    validateStudent(ctx.body, true);
    for(const k of EDITABLE) if(ctx.body[k] !== undefined) s[k] = typeof ctx.body[k] === 'string' ? str(ctx.body[k]) : ctx.body[k];
    if(s.gpa) s.gpa = Number(s.gpa).toFixed(2);
    await docs.put('students', s.studentCode, s);
    await log('STUDENT_UPDATE', user.username, {studentCode: s.studentCode, fields: Object.keys(ctx.body).filter(k => EDITABLE.includes(k))});
    return {student: pubStudent(s)};
  });

  // W9-02: Nhap danh sach sinh vien tot nghiep & lap ho so cap van bang theo lo tu tep CSV (Hoc tu Parchment / BCDiploma)
  router.post('/api/portal/students/import-csv', async ctx => {
    const user = await need(ctx, 'students.write');
    required(ctx.body, ['csvText']);
    const autoProposals = ctx.body.autoCreateProposals !== false;
    const batchNote = str(ctx.body.note, 300) || 'Nhập theo lô từ tệp CSV Phòng Đào tạo';
    const rawLines = String(ctx.body.csvText)
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l.length > 0 && !l.startsWith('#'));

    if(rawLines.length === 0) throw new HttpError(400, 'Tệp CSV rỗng');

    // Neu dong dau tien la header (chua studentCode hoac MSV) thi bo qua
    let startIdx = 0;
    if(/studentCode|mssv|fullName/i.test(rawLines[0])) startIdx = 1;

    let importedCount = 0;
    let updatedCount = 0;
    let proposalCreatedCount = 0;
    const createdRecordIds: string[] = [];
    const errors: {line: number; studentCode?: string; error: string}[] = [];

    for(let i = startIdx; i < rawLines.length; i++) {
      const cols = rawLines[i].split(',').map(c => c.trim());
      // Dinh dang cot: studentCode,fullName,email,nationalId,dateOfBirth,className,major,degreeName,cohort,status,graduationDate,gpa,classification
      const [
        studentCode, fullName, email, nationalId, dateOfBirth = '2005-01-01',
        className = 'K68-CNTT', major = 'Công nghệ thông tin',
        degreeName = 'Cử nhân Công nghệ thông tin', cohort = 'K68',
        statusRaw = 'GRADUATED', graduationDate = '2026-06-30', gpaRaw = '3.20', classification = 'Giỏi'
      ] = cols;

      try {
        const status = (statusRaw || 'GRADUATED').toUpperCase() === 'STUDYING' ? 'STUDYING' : 'GRADUATED';
        const rowObj: any = {
          studentCode, fullName, email, nationalId, dateOfBirth, className, major,
          degreeName, cohort, status,
          graduationDate: status === 'GRADUATED' ? (graduationDate || '2026-06-30') : undefined,
          gpa: status === 'GRADUATED' ? Number(gpaRaw || '3.20').toFixed(2) : undefined,
          classification: status === 'GRADUATED' ? (classification || 'Giỏi') : undefined
        };
        validateStudent(rowObj, false);
        const existing = await docs.get('students', studentCode);
        const studentDoc = {
          ...(existing || {emailActive: true, createdAt: now(), passwordHash: await hashPassword(DEMO_PASSWORD)}),
          ...rowObj
        };
        await docs.put('students', studentCode, studentDoc);
        if(existing) updatedCount++;
        else importedCount++;

        if(autoProposals && status === 'GRADUATED') {
          const allRecs = await docs.list<CredentialRecord>('records');
          const hasActive = allRecs.some(r => r.studentCode === studentCode && r.kind === 'degree' && ACTIVE.includes(r.status));
          if(!hasActive) {
            const rec: CredentialRecord = {
              id: randomUUID(),
              kind: 'degree',
              status: 'PENDING_APPROVAL',
              studentCode,
              studentName: fullName,
              title: degreeName,
              subject: degreeSubject(studentDoc),
              note: batchNote,
              createdBy: user.username,
              createdAt: now(),
              history: [{at: now(), actor: user.username, action: 'BATCH_CSV_CREATE', note: batchNote}]
            };
            await docs.put('records', rec.id, rec);
            proposalCreatedCount++;
            createdRecordIds.push(rec.id);
          }
        }
      } catch (err: any) {
        errors.push({line: i + 1, studentCode, error: err?.message || 'Dữ liệu dòng không hợp lệ'});
      }
    }

    await log('STUDENT_BATCH_CSV_IMPORT', user.username, {importedCount, updatedCount, proposalCreatedCount, errorCount: errors.length});
    return created({importedCount, updatedCount, proposalCreatedCount, createdRecordIds, errors});
  });

  router.get('/api/portal/catalog', async ctx => { await authAsync(ctx); return {courses: COURSE_CATALOG}; });

  // ======================= HO SO CAP VAN BANG =======================
  router.get('/api/portal/records', async ctx => {
    await authAsync(ctx);
    const status = ctx.url.searchParams.get('status');
    const kind = ctx.url.searchParams.get('kind');
    const q = str(ctx.url.searchParams.get('q')).toLowerCase();
    const items = (await docs.list<CredentialRecord>('records'))
      .filter(r => (!status || r.status === status) && (!kind || r.kind === kind)
        && (!q || `${r.studentCode} ${r.studentName} ${r.title} ${r.id}`.toLowerCase().includes(q)))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return {items: items.map(summary)};
  });

  router.get('/api/portal/records/:id', async ctx => {
    await authAsync(ctx);
    const r = await getRecord(ctx.params.id);
    return {record: r, revokedOnList: r.statusListIndex !== undefined ? r.status === 'REVOKED' : false};
  });

  async function ensureNoActive(studentCode: string, kind: RecordKind, courseCode?: string) {
    const dup = (await docs.list<CredentialRecord>('records')).find(r =>
      r.studentCode === studentCode && ACTIVE.includes(r.status) &&
      (kind === 'course' ? r.kind === 'course' && r.subject.courseCode === courseCode : r.kind !== 'course'));
    if(dup) throw new HttpError(409, `Sinh viên đã có hồ sơ đang hiệu lực (${dup.title} – ${dup.status}). Hãy thu hồi trước khi lập hồ sơ mới`);
  }

  router.post('/api/portal/records', async ctx => {
    const user = await need(ctx, 'records.create');
    required(ctx.body, ['studentCode', 'kind']);
    return docs.atomic(async () => {
      const s = await getStudent(str(ctx.body.studentCode));
      const kind = ctx.body.kind as RecordKind;
      let rec: CredentialRecord;
      const base = {id: randomUUID(), status: 'PENDING_APPROVAL' as RecordStatus, studentCode: s.studentCode, studentName: s.fullName,
        note: str(ctx.body.note, 500) || undefined, createdBy: user.username, createdAt: now(), history: []};
      if(kind === 'degree') {
        if(s.status !== 'GRADUATED' || !s.graduationDate || !s.gpa) throw new HttpError(400, 'Sinh viên chưa đủ điều kiện tốt nghiệp (thiếu quyết định tốt nghiệp / GPA)');
        await ensureNoActive(s.studentCode, 'degree');
        rec = {...base, kind, title: s.degreeName, subject: degreeSubject(s)};
      } else if(kind === 'course') {
        required(ctx.body, ['courseCode', 'grade']);
        const c = COURSE_CATALOG.find(x => x.courseCode === ctx.body.courseCode);
        if(!c) throw new HttpError(400, 'Mã học phần không có trong danh mục');
        if(!/^(A\+|A|B\+|B|C\+|C|D\+|D)$/.test(String(ctx.body.grade))) throw new HttpError(400, 'Điểm chữ không hợp lệ (A+ … D)');
        await ensureNoActive(s.studentCode, 'course', c.courseCode);
        rec = {...base, kind, title: `${c.courseName} (${c.courseCode})`, subject: {
          studentName: s.fullName, courseCode: c.courseCode, courseName: c.courseName, courseHours: c.courseHours,
          completionDate: str(ctx.body.completionDate, 10) || now().slice(0, 10), grade: String(ctx.body.grade), skills: c.skills, certificateValid: true
        }};
      } else throw new HttpError(400, 'Loại văn bằng không hợp lệ');
      push(rec, user.username, 'CREATE', rec.note);
      await docs.put('records', rec.id, rec);
      await log('RECORD_CREATE', user.username, {recordId: rec.id, kind, studentCode: s.studentCode});
      return created({record: summary(rec)});
    });
  });

  // So hoa so goc: chuyen vien doi chieu so goc giay + tai ban scan -> bam SHA-256 -> cho lanh dao ky
  router.post('/api/portal/records/legacy', async ctx => {
    const user = await need(ctx, 'records.create');
    required(ctx.body, ['studentCode', 'registryBookNumber', 'degreeSerial', 'originalIssueDate']);
    return docs.atomic(async () => {
      const s = await getStudent(str(ctx.body.studentCode));
      if(s.status !== 'GRADUATED') throw new HttpError(400, 'Chỉ số hóa văn bằng cho sinh viên đã tốt nghiệp');
      await ensureNoActive(s.studentCode, 'legacy_degree');
      let scan: Buffer;
      const uploaded = typeof ctx.body.scanBase64 === 'string' && ctx.body.scanBase64.length > 0;
      if(uploaded) {
        scan = Buffer.from(ctx.body.scanBase64, 'base64');
        if(scan.length > 4_000_000) throw new HttpError(413, 'Tệp scan vượt quá 4 MB');
      } else scan = d.sampleScan();
      const digest = computeDocumentDigest(scan);
      d.registerScan(digest, scan);
      if(uploaded) await docs.put('scans', digest, {b64: scan.toString('base64'), name: str(ctx.body.scanName, 120), at: now()});
      const rec: CredentialRecord = {
        id: randomUUID(), kind: 'legacy_degree', status: 'PENDING_APPROVAL', studentCode: s.studentCode, studentName: s.fullName,
        title: `${s.degreeName} (số hóa từ sổ gốc)`, subject: degreeSubject(s),
        legacy: {originalIssueDate: str(ctx.body.originalIssueDate, 10), registryBookNumber: str(ctx.body.registryBookNumber, 40), degreeSerial: str(ctx.body.degreeSerial, 40), digest, scanBytes: scan.length, uploaded},
        note: str(ctx.body.note, 500) || undefined, createdBy: user.username, createdAt: now(), history: []
      };
      push(rec, user.username, 'LEGACY_INGEST', `Đối chiếu sổ ${rec.legacy!.registryBookNumber}, số hiệu ${rec.legacy!.degreeSerial}`);
      await docs.put('records', rec.id, rec);
      await log('LEGACY_INGEST', user.username, {recordId: rec.id, studentCode: s.studentCode, digest});
      return created({record: summary(rec)});
    });
  });

  async function approveRecord(id: string, user: StaffUser, note?: string, action = 'APPROVE') {
    const r = await getRecord(id);
    if(r.status !== 'PENDING_APPROVAL') throw new HttpError(409, 'Hồ sơ không ở trạng thái chờ phê duyệt');
    if(r.createdBy === user.username) throw new HttpError(403, 'Nguyên tắc 4 mắt: người lập hồ sơ không được tự phê duyệt', 'SOD_VIOLATION');
    if(r.kind === 'legacy_degree' && !r.provenance) {
      r.provenance = await signLegacyProvenance({
        originalIssueDate: r.legacy!.originalIssueDate, registryBookNumber: r.legacy!.registryBookNumber, degreeSerial: r.legacy!.degreeSerial,
        sourceDocumentType: 'paper_ledger_scan', sourceDocumentDigest: r.legacy!.digest,
        verificationMethod: 'physical_ledger_reconciliation', verifiedBy: r.createdBy,
        approvedBy: user.username, approvalTimestamp: now(), approverDid: d.approverKeyPair.id
      }, d.approverKeyPair);
    }
    if(r.reissueOf) {
      const old = await docs.get<CredentialRecord>('records', r.reissueOf);
      if(old && ['ISSUED', 'SUSPENDED'].includes(old.status)) {
        await revokeRecord(old, user.username, `Thu hồi để cấp lại: ${r.note ?? 'mất thiết bị'}`);
        old.reissuedBy = r.id;
        await docs.put('records', old.id, old);
      }
    }
    r.status = 'APPROVED'; r.approvedBy = user.username; r.approvedAt = now();
    push(r, user.username, action, note);
    await docs.put('records', r.id, r);
    await log('RECORD_APPROVE', user.username, {recordId: r.id, kind: r.kind, studentCode: r.studentCode});
    return r;
  }

  router.post('/api/portal/records/:id/approve', async ctx => {
    const user = await need(ctx, 'records.approve');
    return docs.atomic(async () => ({
      record: summary(await approveRecord(ctx.params.id, user, str(ctx.body.note, 500) || undefined))
    }));
  });

  router.post('/api/portal/records/:id/reject', async ctx => {
    const user = await need(ctx, 'records.approve');
    required(ctx.body, ['reason']);
    return docs.atomic(async () => {
      const r = await getRecord(ctx.params.id);
      if(r.status !== 'PENDING_APPROVAL') throw new HttpError(409, 'Hồ sơ không ở trạng thái chờ phê duyệt');
      r.status = 'REJECTED'; r.rejectedBy = user.username; r.rejectReason = str(ctx.body.reason, 500);
      push(r, user.username, 'REJECT', r.rejectReason);
      await docs.put('records', r.id, r);
      await log('RECORD_REJECT', user.username, {recordId: r.id, studentCode: r.studentCode});
      return {record: summary(r)};
    });
  });

  router.post('/api/portal/records/:id/cancel', async ctx => {
    const user = await need(ctx, 'records.create');
    return docs.atomic(async () => {
      const r = await getRecord(ctx.params.id);
      if(r.createdBy !== user.username) throw new HttpError(403, 'Chỉ người lập hồ sơ mới được hủy');
      if(r.status !== 'PENDING_APPROVAL' && r.status !== 'REJECTED') throw new HttpError(409, 'Chỉ hủy được hồ sơ đang chờ duyệt hoặc bị từ chối');
      r.status = 'CANCELLED';
      push(r, user.username, 'CANCEL');
      await docs.put('records', r.id, r);
      await log('RECORD_CANCEL', user.username, {recordId: r.id});
      return {record: summary(r)};
    });
  });

  router.post('/api/portal/records/:id/revoke', async ctx => {
    const user = await need(ctx, 'records.revoke');
    required(ctx.body, ['reason']);
    return docs.atomic(async () => {
      const r = await getRecord(ctx.params.id);
      if(r.status === 'APPROVED') {
        r.status = 'CANCELLED';
        push(r, user.username, 'CANCEL_BEFORE_CLAIM', str(ctx.body.reason, 500));
        await docs.put('records', r.id, r);
        await log('RECORD_CANCEL', user.username, {recordId: r.id, reason: str(ctx.body.reason, 500)});
        return {record: summary(r)};
      }
      if(r.status !== 'ISSUED' && r.status !== 'SUSPENDED') throw new HttpError(409, 'Chỉ thu hồi được văn bằng đã phát hành hoặc đang tạm đình chỉ');
      await revokeRecord(r, user.username, str(ctx.body.reason, 500));
      return {record: summary(r), statusListUrl: d.statusRegistry.listUrl};
    });
  });

  // W9-02: Phe duyet ho so cap van bang theo lo (Batch Approve) danh cho Truong phong Dao tao (co kiem tra 4 mat SoD)
  router.post('/api/portal/records/batch-approve', async ctx => {
    const user = await need(ctx, 'records.approve');
    required(ctx.body, ['recordIds']);
    if(!Array.isArray(ctx.body.recordIds) || ctx.body.recordIds.length === 0) {
      throw new HttpError(400, 'Danh sách hồ sơ cần phê duyệt không được rỗng');
    }
    const approvedIds: string[] = [];
    const skipped: {id: string; reason: string; code?: string}[] = [];
    const note = str(ctx.body.note, 500) || 'Phê duyệt theo lô bởi Lãnh đạo Phòng Đào tạo';

    if(ctx.body.recordIds.length > 100) throw new HttpError(400, 'Tối đa 100 hồ sơ mỗi lần duyệt');
    for(const id of new Set<string>(ctx.body.recordIds.map(String))) {
      try {
        await docs.atomic(() => approveRecord(id, user, note, 'BATCH_APPROVE'));
        approvedIds.push(id);
      } catch(error) {
        if(!(error instanceof HttpError)) throw error;
        skipped.push({id, reason: error.message, code: error.code});
      }
    }

    await log('RECORD_BATCH_APPROVE', user.username, {approvedCount: approvedIds.length, skippedCount: skipped.length});
    return {approvedCount: approvedIds.length, approvedIds, skipped};
  });

  // W9-04: Tam dinh chi hieu luc van bang (SUSPEND) va Khoi phuc hieu luc (REINSTATE) theo chuan Europass EDC / EBSI
  router.post('/api/portal/records/:id/suspend', async ctx => {
    const user = await need(ctx, 'records.revoke');
    required(ctx.body, ['reason']);
    return docs.atomic(async () => {
      const r = await getRecord(ctx.params.id);
      if(r.status !== 'ISSUED') throw new HttpError(409, 'Chỉ tạm đình chỉ được văn bằng đang ở trạng thái ĐÃ PHÁT HÀNH (ISSUED)');
      r.status = 'SUSPENDED';
      r.suspendedBy = user.username;
      r.suspendedAt = now();
      r.suspendReason = str(ctx.body.reason, 500);
      push(r, user.username, 'SUSPEND', r.suspendReason);
      await docs.put('records', r.id, r);
      await log('RECORD_SUSPEND', user.username, {recordId: r.id, statusListIndex: r.statusListIndex, reason: r.suspendReason});
      return {record: summary(r), statusListUrl: d.statusRegistry.listUrl};
    });
  });

  router.post('/api/portal/records/:id/reinstate', async ctx => {
    const user = await need(ctx, 'records.revoke');
    return docs.atomic(async () => {
      const r = await getRecord(ctx.params.id);
      if(r.status !== 'SUSPENDED') throw new HttpError(409, 'Chỉ khôi phục được văn bằng đang ở trạng thái TẠM ĐÌNH CHỈ (SUSPENDED)');
      r.status = 'ISSUED';
      push(r, user.username, 'REINSTATE', str(ctx.body.note, 500) || 'Khôi phục hiệu lực văn bằng sau khi xác minh học vụ');
      await docs.put('records', r.id, r);
      await log('RECORD_REINSTATE', user.username, {recordId: r.id, statusListIndex: r.statusListIndex});
      return {record: summary(r), statusListUrl: d.statusRegistry.listUrl};
    });
  });

  // ======================= KIEM TOAN / HE THONG / RBAC DONG =======================
  router.get('/api/portal/audit', async ctx => {
    await need(ctx, 'audit.read');
    const limit = Math.min(Number(ctx.url.searchParams.get('limit')) || 200, 500);
    return {items: await audit.listAudit(limit), total: await audit.auditCount()};
  });

  router.get('/api/portal/status-list', async ctx => {
    await authAsync(ctx);
    await restoreStatus();
    const records = await docs.list<CredentialRecord>('records');
    return {
      url: d.statusUrl, statusListUrl: d.statusRegistry.listUrl, capacity: d.statusRegistry.list.length,
      etag: d.statusRegistry.etag, suspensionUrl: d.suspensionRegistry.listUrl,
      suspensionEtag: d.suspensionRegistry.etag, allocated: d.statusRegistry.allocatedCount,
      revoked: records.filter(r => r.status === 'REVOKED').length,
      suspended: records.filter(r => r.status === 'SUSPENDED').length,
      issuerDid: d.issuerDid, signingKey: d.issuerKeyPair.id, approverKey: d.approverKeyPair.id
    };
  });

  // W9-04: Kiem tra trang thai Key Vault (Envelope Encryption AES-256-GCM)
  router.get('/api/portal/key-vault', async ctx => {
    await need(ctx, 'users.manage');
    const vault = await docs.get('keys', d.issuerDid);
    return {
      issuerDid: d.issuerDid,
      vaultVersion: vault?.vaultVersion ?? '1.0',
      issuerEnvelope: vault?.issuer ? {
        id: vault.issuer.id,
        type: vault.issuer.type,
        cipher: vault.issuer.cipher,
        kdf: vault.issuer.kdf,
        keyId: vault.issuer.keyId,
        publicKeyMultibase: vault.issuer.publicKeyMultibase,
        sealedAt: vault.issuer.sealedAt,
        hasPlaintextPrivateKey: !!vault.issuer.secretKeyMultibase
      } : null,
      approverEnvelope: vault?.approver ? {
        id: vault.approver.id,
        type: vault.approver.type,
        cipher: vault.approver.cipher,
        kdf: vault.approver.kdf,
        keyId: vault.approver.keyId,
        publicKeyMultibase: vault.approver.publicKeyMultibase,
        sealedAt: vault.approver.sealedAt,
        hasPlaintextPrivateKey: !!vault.approver.secretKeyMultibase
      } : null
    };
  });

  // W9-01: Quan tri Ma tran Phan quyen RBAC Dong tren PostgreSQL
  router.get('/api/portal/rbac', async ctx => {
    await need(ctx, 'users.manage');
    const roles = await docs.list('rbac_roles');
    return {roles};
  });

  router.put('/api/portal/rbac/:role', async ctx => {
    const user = await need(ctx, 'users.manage');
    const role = String(ctx.params.role).toUpperCase() as IssuerRole;
    if(!['ADMIN', 'REGISTRAR', 'APPROVER'].includes(role)) throw new HttpError(400, 'Vai trò không hợp lệ');
    if(!Array.isArray(ctx.body.permissions)) throw new HttpError(400, 'permissions phải là mảng chuỗi');
    const validPerms = ['students.write', 'records.create', 'records.approve', 'records.revoke', 'audit.read', 'users.manage'];
    const permissions = ctx.body.permissions.map(String).filter((p: string) => validPerms.includes(p));
    if(role === 'ADMIN' && !permissions.includes('users.manage')) {
      throw new HttpError(400, 'Không thể gỡ quyền users.manage khỏi vai trò ADMIN');
    }
    const updated = {role, label: ROLE_LABEL[role], permissions, updatedAt: now(), updatedBy: user.username};
    await docs.put('rbac_roles', role, updated);
    await log('RBAC_POLICY_UPDATE', user.username, {role, permissions});
    return {rolePolicy: updated};
  });

  router.get('/api/portal/users', async ctx => {
    await need(ctx, 'users.manage');
    return {items: (await docs.list('users')).map(pubUser).sort((a: any, b: any) => a.username.localeCompare(b.username))};
  });

  router.post('/api/portal/users', async ctx => {
    const user = await need(ctx, 'users.manage');
    required(ctx.body, ['username', 'fullName', 'email', 'role', 'password']);
    const username = str(ctx.body.username, 32).toLowerCase();
    if(!/^[a-z0-9._-]{3,32}$/.test(username)) throw new HttpError(400, 'Tên đăng nhập chỉ gồm chữ thường, số, dấu chấm, gạch (3–32 ký tự)');
    if(!['ADMIN', 'REGISTRAR', 'APPROVER'].includes(ctx.body.role)) throw new HttpError(400, 'Vai trò không hợp lệ');
    const pe = passwordPolicyError(ctx.body.password);
    if(pe) throw new HttpError(400, pe);
    if(await docs.get('users', username)) throw new HttpError(409, 'Tên đăng nhập đã tồn tại');
    const u = {username, fullName: str(ctx.body.fullName), email: str(ctx.body.email), role: ctx.body.role, title: str(ctx.body.title) || ROLE_LABEL[ctx.body.role as IssuerRole],
      active: true, passwordHash: await hashPassword(ctx.body.password), createdAt: now(), createdBy: user.username};
    await docs.put('users', username, u);
    await log('USER_CREATE', user.username, {username, role: u.role});
    return created({user: pubUser(u)});
  });

  router.put('/api/portal/users/:username/role', async ctx => {
    const user = await need(ctx, 'users.manage');
    required(ctx.body, ['role']);
    const u = await docs.get('users', ctx.params.username);
    if(!u) throw new HttpError(404, 'Không tìm thấy tài khoản');
    if(!['ADMIN', 'REGISTRAR', 'APPROVER'].includes(ctx.body.role)) throw new HttpError(400, 'Vai trò không hợp lệ');
    const oldRole = u.role;
    u.role = ctx.body.role as IssuerRole;
    u.title = str(ctx.body.title) || ROLE_LABEL[u.role];
    await docs.put('users', u.username, u);
    await log('USER_ROLE_CHANGE', user.username, {username: u.username, oldRole, newRole: u.role});
    return {user: pubUser(u)};
  });

  router.post('/api/portal/users/:username/toggle', async ctx => {
    const user = await need(ctx, 'users.manage');
    const u = await docs.get('users', ctx.params.username);
    if(!u) throw new HttpError(404, 'Không tìm thấy tài khoản');
    if(u.username === user.username) throw new HttpError(400, 'Không thể tự khóa tài khoản của chính mình');
    u.active = !u.active;
    u.sessionVersion = randomUUID();
    await docs.put('users', u.username, u);

    await log(u.active ? 'USER_UNLOCK' : 'USER_LOCK', user.username, {username: u.username});
    return {user: pubUser(u)};
  });

  router.post('/api/portal/users/:username/reset-password', async ctx => {
    const user = await need(ctx, 'users.manage');
    const u = await docs.get('users', ctx.params.username);
    if(!u) throw new HttpError(404, 'Không tìm thấy tài khoản');
    const pe = passwordPolicyError(ctx.body.password);
    if(pe) throw new HttpError(400, pe);
    u.passwordHash = await hashPassword(ctx.body.password);
    u.sessionVersion = randomUUID();
    await docs.put('users', u.username, u);

    await log('USER_RESET_PASSWORD', user.username, {username: u.username});
    return {ok: true};
  });

  // ======================= API CHO VI SINH VIEN (Bearer token & OIDC / VNeID id_token) =======================
  // Nha truong dong vai tro nha cung cap dinh danh: SSO email truong (sinh vien dang hoc) hoac VNeID (cuu sinh vien).
  router.post('/api/student-auth/login', async ctx => {
    required(ctx.body, ['method', 'identifier', 'password']);
    const method = ctx.body.method === 'vneid' ? 'vneid' : 'sso';
    const ident = str(ctx.body.identifier, 120).toLowerCase();
    const key = `stu|${clientIp(ctx.req)}|${ident}`;
    const wait = throttle.check(key);
    if(wait) throw new HttpError(429, `Đăng nhập sai quá nhiều lần. Thử lại sau ${wait} giây`);
    const students = await docs.list('students');
    const s = method === 'sso' ? students.find(x => x.email.toLowerCase() === ident) : students.find(x => x.nationalId === ident);
    if(!s || !(await verifyPassword(String(ctx.body.password), s.passwordHash))) {
      throttle.fail(key);
      throw new HttpError(401, method === 'sso' ? 'Email trường hoặc mật khẩu không đúng' : 'Số CCCD hoặc mật khẩu VNeID không đúng');
    }
    if(method === 'sso' && !s.emailActive) {
      throw new HttpError(403, 'Email trường của bạn đã bị thu hồi sau khi tốt nghiệp. Vui lòng đăng nhập bằng VNeID', 'EMAIL_DEACTIVATED');
    }
    throttle.success(key);
    await log('STUDENT_LOGIN', `student:${s.studentCode}`, {method});
    const id_token = d.oidcProvider
      ? await d.oidcProvider.issueIdToken({
          studentCode: s.studentCode,
          fullName: s.fullName,
          email: s.email,
          nationalId: s.nationalId,
          method
        })
      : undefined;
    return {
      token: signToken({iss: d.issuerDid, sub: s.studentCode, method, aud: 'wallet'}, 2 * 3600),
      id_token,
      student: pubStudent(s),
      method
    };
  });

  // W9-05: Xac minh id_token ES256 chuan OIDC / VNeID & Chung thuc khoa WebCrypto non-extractable
  router.post('/api/student-auth/verify-id-token', async ctx => {
    required(ctx.body, ['id_token']);
    if(!d.oidcProvider) throw new HttpError(500, 'OIDC Provider chưa được khởi tạo');
    const claims = await d.oidcProvider.verifyIdToken(String(ctx.body.id_token));
    if(!claims) throw new HttpError(401, 'id_token không hợp lệ hoặc chữ ký ES256 không khớp', 'INVALID_ID_TOKEN');
    return {valid: true, claims};
  });

  router.post('/api/student-auth/webcrypto-attest', async ctx => {
    const challenge = str(ctx.body?.challenge, 120) || randomBytes(16).toString('base64url');
    const audience = str(ctx.body?.audience, 120) || d.issuerDid;
    const attestation = await createWebCryptoNonExtractableProof(challenge, audience);
    return {attestation};
  });

  function studentAuth(ctx: RouteCtx): string {
    const t = verifyToken<{sub: string; aud: string; iss: string}>((ctx.req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if(!t || t.aud !== 'wallet' || t.iss !== d.issuerDid || typeof t.sub !== 'string') throw new HttpError(401, 'Token sinh viên không hợp lệ hoặc đã hết hạn', 'UNAUTHENTICATED');
    return t.sub;
  }

  router.get('/api/student/me', async ctx => {
    const code = studentAuth(ctx);
    const s = await getStudent(code);
    const records = (await docs.list<CredentialRecord>('records')).filter(r => r.studentCode === code && ['APPROVED', 'ISSUED', 'SUSPENDED', 'REVOKED', 'PENDING_APPROVAL'].includes(r.status))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(r => ({id: r.id, kind: r.kind, title: r.title, status: r.status, holderDid: r.holderDid, issuedAt: r.issuedAt, approvedAt: r.approvedAt,
        revokeReason: r.revokeReason, reissueOf: r.reissueOf, reissuedBy: r.reissuedBy}));
    return {student: pubStudent(s), records, issuerDid: d.issuerDid};
  });

  router.post('/api/student/nonce', async ctx => {
    const code = studentAuth(ctx);
    const c_nonce = randomBytes(24).toString('base64url');
    for(const [k, v] of nonces) if(v.exp < Date.now()) nonces.delete(k);
    if(nonces.size >= 1000 || [...nonces.values()].filter(item => item.studentCode === code).length >= 10) {
      throw new HttpError(429, 'Quá nhiều yêu cầu nhận văn bằng đang chờ');
    }
    nonces.set(c_nonce, {studentCode: code, exp: Date.now() + 120_000});
    return {c_nonce, expires_in: 120, aud: d.issuerUrl};
  });

  // Nhan van bang (kieu OpenID4VCI): vi chung minh nam giu khoa rieng cua holder DID bang chu ky tren c_nonce
  router.post('/api/student/claim', async ctx => {
    const code = studentAuth(ctx);
    required(ctx.body, ['recordId', 'holderDid', 'c_nonce', 'proof']);
    const n = nonces.get(ctx.body.c_nonce);
    if(!n || n.studentCode !== code || n.exp < Date.now()) throw new HttpError(400, 'c_nonce không hợp lệ hoặc đã hết hạn');
    const holderDid = String(ctx.body.holderDid);
    if(!/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(holderDid)) throw new HttpError(400, 'holderDid phải là did:key');
    if(!await verifyCredentialProof(ctx.body.proof, holderDid, ctx.body.c_nonce, d.issuerUrl)) {
      throw new HttpError(401, 'Chữ ký chứng minh sở hữu khóa không hợp lệ', 'BAD_PROOF');
    }
    return docs.atomic(async () => {
      if(nonces.get(ctx.body.c_nonce) !== n || n.exp <= Date.now()) throw new HttpError(400, 'c_nonce không còn hiệu lực');
      nonces.delete(ctx.body.c_nonce);
      const r = await getRecord(String(ctx.body.recordId));
      if(r.studentCode !== code) throw new HttpError(403, 'Văn bằng này không thuộc về bạn');
      if(r.status === 'ISSUED' && r.holderDid === holderDid && r.credential) {
        return {recordId: r.id, statusListIndex: r.statusListIndex, credential: r.credential};
      }
      if(r.status === 'ISSUED') throw new HttpError(409, 'Văn bằng đã được nhận vào một ví khác. Nếu mất thiết bị, hãy gửi yêu cầu cấp lại');
      if(r.status !== 'APPROVED') throw new HttpError(409, 'Văn bằng chưa được phê duyệt để phát hành');
      const {index, credential} = await issueVc(r, holderDid);
      r.status = 'ISSUED'; r.issuedAt = now(); r.holderDid = holderDid; r.statusListIndex = index; r.credential = credential;
      push(r, `student:${code}`, 'CLAIM', `Ký phát hành vào ví ${holderDid.slice(0, 24)}…`);
      await docs.put('records', r.id, r);
      await log('CREDENTIAL_ISSUE', `student:${code}`, {recordId: r.id, statusListIndex: index});
      return {recordId: r.id, statusListIndex: index, credential};
    });
  });

  router.post('/api/student/reissue', async ctx => {
    const code = studentAuth(ctx);
    required(ctx.body, ['recordId', 'reason']);
    return docs.atomic(async () => {
      const old = await getRecord(String(ctx.body.recordId));
      if(old.studentCode !== code) throw new HttpError(403, 'Văn bằng này không thuộc về bạn');
      if(!['ISSUED', 'SUSPENDED', 'REVOKED'].includes(old.status)) throw new HttpError(409, 'Chỉ yêu cầu cấp lại cho văn bằng đã phát hành');
      const all = await docs.list<CredentialRecord>('records');
      if(all.some(r => r.reissueOf === old.id && ['PENDING_APPROVAL', 'APPROVED'].includes(r.status))) throw new HttpError(409, 'Đã có yêu cầu cấp lại đang được xử lý');
      const rec: CredentialRecord = {
        id: randomUUID(), kind: old.kind, status: 'PENDING_APPROVAL', studentCode: old.studentCode, studentName: old.studentName,
        title: old.title, subject: old.subject, legacy: old.legacy, provenance: old.provenance, reissueOf: old.id,
        note: `Sinh viên yêu cầu cấp lại: ${str(ctx.body.reason, 300)}`, createdBy: `student:${code}`, createdAt: now(), history: []
      };
      push(rec, `student:${code}`, 'REISSUE_REQUEST', str(ctx.body.reason, 300));
      await docs.put('records', rec.id, rec);
      await log('REISSUE_REQUEST', `student:${code}`, {recordId: rec.id, reissueOf: old.id});
      return created({record: {id: rec.id, status: rec.status, title: rec.title}});
    });
  });

  // Khoi phuc Bitstring Status List tu CSDL sau khi khoi dong lai container
  async function restoreStatus() {
    await docs.atomic(async () => {
      const records = await docs.list<CredentialRecord>('records');
      const issued = records.filter(r => Number.isInteger(r.statusListIndex));
      const next = issued.reduce((max, r) => Math.max(max, r.statusListIndex! + 1), 1);
      // Credentials issued by older releases contain only a revocation entry.
      const blocked = issued.filter(r => r.status === 'REVOKED' ||
        (r.status === 'SUSPENDED' && !Array.isArray(r.credential?.credentialStatus)));
      await d.statusRegistry.restore(next, blocked.map(r => r.statusListIndex!));
      await d.suspensionRegistry.restore(next, issued.filter(r => r.status === 'SUSPENDED').map(r => r.statusListIndex!));
    });
  }

  return {router, sessions, restoreStatus};
}

export type IssuerPortal = Awaited<ReturnType<typeof createIssuerPortal>>;
