import {randomBytes, randomUUID} from 'node:crypto';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {issueSelectiveDisclosureVc} from '../crypto/holder-binding.js';
import {computeDocumentDigest, signLegacyProvenance} from '../crypto/provenance-signer.js';
import {buildUnsignedDegreeVc, DEGREE_MANDATORY_POINTERS, LEGACY_DEGREE_MANDATORY_POINTERS} from '../profiles/degree-profile.js';
import {buildUnsignedCourseVc, COURSE_MANDATORY_POINTERS} from '../profiles/course-profile.js';
import type {IssuerStatusRegistry} from '../status/status-store.js';
import type {AuditStore} from '../infra/postgres-store.js';
import type {DocStore} from '../infra/doc-store.js';
import {hashPassword, verifyPassword, passwordPolicyError} from '../auth/password.js';
import {SessionManager, LoginThrottle, signToken, verifyToken, clientIp} from '../auth/session.js';
import {Router, HttpError, created, required, str, RouteCtx} from './router.js';
import {DEMO_PASSWORD, ISSUER_USERS, STUDENTS, COURSE_CATALOG, IssuerRole, StudentProfile} from './seed-data.js';

export interface IssuerPortalDeps {
  docs: DocStore;
  audit: AuditStore;
  statusRegistry: IssuerStatusRegistry;
  issuerKeyPair: any;
  approverKeyPair: any;
  documentLoader: any;
  issuerDid: string;
  statusUrl: string;
  sampleScan: () => Buffer;
  registerScan: (digest: string, scan: Buffer) => void;
}

interface StaffUser { username: string; fullName: string; email: string; role: IssuerRole; title: string }

type RecordKind = 'degree' | 'course' | 'legacy_degree';
type RecordStatus = 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'CANCELLED' | 'ISSUED' | 'REVOKED';

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
  revokedBy?: string; revokedAt?: string; revokeReason?: string;
  history: {at: string; actor: string; action: string; note?: string}[];
}

export const ISSUER_PERMISSIONS: Record<IssuerRole, string[]> = {
  ADMIN: ['students.write', 'audit.read', 'users.manage'],
  REGISTRAR: ['students.write', 'records.create'],
  APPROVER: ['records.approve', 'records.revoke', 'audit.read']
};

const ROLE_LABEL: Record<IssuerRole, string> = {ADMIN: 'Quản trị hệ thống', REGISTRAR: 'Chuyên viên Đào tạo', APPROVER: 'Lãnh đạo phê duyệt'};
const ACTIVE: RecordStatus[] = ['PENDING_APPROVAL', 'APPROVED', 'ISSUED'];

const now = () => new Date().toISOString();
const pubUser = (u: any) => { const {passwordHash, ...rest} = u; return rest; };
const pubStudent = (s: any) => { const {passwordHash, ...rest} = s; return rest; };
const summary = (r: CredentialRecord) => { const {credential, ...rest} = r; return {...rest, hasCredential: !!credential}; };

export async function createIssuerPortal(d: IssuerPortalDeps) {
  const {docs, audit} = d;
  const sessions = new SessionManager<StaffUser>('iss_sid');
  const throttle = new LoginThrottle();
  const nonces = new Map<string, {studentCode: string; exp: number}>();

  // ---------- Seed du lieu demo (chi khi CSDL trong) ----------
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

  function auth(ctx: RouteCtx): StaffUser {
    const s = sessions.get(ctx.req);
    if(!s) throw new HttpError(401, 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại', 'UNAUTHENTICATED');
    return s.user;
  }
  async function need(ctx: RouteCtx, perm: string): Promise<StaffUser> {
    const u = auth(ctx);
    if(!ISSUER_PERMISSIONS[u.role].includes(perm)) {
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
    const index = d.statusRegistry.allocateIndex();
    if(r.kind === 'course') {
      const from = new Date();
      const until = new Date(from); until.setFullYear(until.getFullYear() + 2);
      const unsigned = buildUnsignedCourseVc({
        holderDid, statusListIndex: index, statusListUrl: d.statusUrl, issuerDid: d.issuerDid, subject: r.subject,
        validFrom: from.toISOString().slice(0, 19) + 'Z', validUntil: until.toISOString().slice(0, 19) + 'Z'
      });
      return {index, credential: await issueSelectiveDisclosureVc({unsignedCredential: unsigned, issuerKeyPair: d.issuerKeyPair, mandatoryPointers: COURSE_MANDATORY_POINTERS, documentLoader: d.documentLoader})};
    }
    const unsigned = buildUnsignedDegreeVc({
      holderDid, statusListIndex: index, statusListUrl: d.statusUrl, issuerDid: d.issuerDid,
      subject: r.subject as any, legacyProvenance: r.kind === 'legacy_degree' ? r.provenance : undefined
    });
    const pointers = r.kind === 'legacy_degree' ? LEGACY_DEGREE_MANDATORY_POINTERS : DEGREE_MANDATORY_POINTERS;
    return {index, credential: await issueSelectiveDisclosureVc({unsignedCredential: unsigned, issuerKeyPair: d.issuerKeyPair, mandatoryPointers: pointers, documentLoader: d.documentLoader})};
  }

  async function revokeRecord(r: CredentialRecord, actor: string, reason: string) {
    if(r.statusListIndex !== undefined) await d.statusRegistry.setRevoked(r.statusListIndex, true);
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
    if(!u.active) throw new HttpError(403, 'Tài khoản đã bị khóa. Liên hệ quản trị hệ thống');
    throttle.success(key);
    const user: StaffUser = {username: u.username, fullName: u.fullName, email: u.email, role: u.role, title: u.title};
    sessions.create(user, ctx.req, ctx.res);
    u.lastLoginAt = now();
    await docs.put('users', u.username, u);
    await log('LOGIN', u.username, {role: u.role});
    return {user, permissions: ISSUER_PERMISSIONS[user.role]};
  });

  router.post('/api/portal/auth/logout', async ctx => {
    const s = sessions.get(ctx.req);
    sessions.destroy(ctx.req, ctx.res);
    if(s) await log('LOGOUT', s.user.username);
    return {ok: true};
  });

  router.get('/api/portal/auth/me', async ctx => {
    const user = auth(ctx);
    return {user, permissions: ISSUER_PERMISSIONS[user.role], issuerDid: d.issuerDid};
  });

  router.post('/api/portal/auth/change-password', async ctx => {
    const user = auth(ctx);
    required(ctx.body, ['current', 'next']);
    const u = await docs.get('users', user.username);
    if(!(await verifyPassword(String(ctx.body.current), u.passwordHash))) throw new HttpError(400, 'Mật khẩu hiện tại không đúng');
    const err = passwordPolicyError(ctx.body.next);
    if(err) throw new HttpError(400, err);
    u.passwordHash = await hashPassword(ctx.body.next);
    await docs.put('users', u.username, u);
    await log('PASSWORD_CHANGE', user.username);
    return {ok: true};
  });

  // ======================= TONG QUAN =======================
  router.get('/api/portal/dashboard', async ctx => {
    const user = auth(ctx);
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
    auth(ctx);
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
    auth(ctx);
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

  router.get('/api/portal/catalog', async ctx => { auth(ctx); return {courses: COURSE_CATALOG}; });

  // ======================= HO SO CAP VAN BANG =======================
  router.get('/api/portal/records', async ctx => {
    auth(ctx);
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
    auth(ctx);
    const r = await getRecord(ctx.params.id);
    return {record: r, revokedOnList: r.statusListIndex !== undefined ? d.statusRegistry.isRevoked(r.statusListIndex) : false};
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

  // So hoa so goc: chuyen vien doi chieu so goc giay + tai ban scan -> bam SHA-256 -> cho lanh dao ky
  router.post('/api/portal/records/legacy', async ctx => {
    const user = await need(ctx, 'records.create');
    required(ctx.body, ['studentCode', 'registryBookNumber', 'degreeSerial', 'originalIssueDate']);
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

  router.post('/api/portal/records/:id/approve', async ctx => {
    const user = await need(ctx, 'records.approve');
    const r = await getRecord(ctx.params.id);
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
      if(old && old.status === 'ISSUED') {
        await revokeRecord(old, user.username, `Thu hồi để cấp lại: ${r.note ?? 'mất thiết bị'}`);
        old.reissuedBy = r.id;
        await docs.put('records', old.id, old);
      }
    }
    r.status = 'APPROVED'; r.approvedBy = user.username; r.approvedAt = now();
    push(r, user.username, 'APPROVE', str(ctx.body.note, 500) || undefined);
    await docs.put('records', r.id, r);
    await log('RECORD_APPROVE', user.username, {recordId: r.id, kind: r.kind, studentCode: r.studentCode});
    return {record: summary(r)};
  });

  router.post('/api/portal/records/:id/reject', async ctx => {
    const user = await need(ctx, 'records.approve');
    required(ctx.body, ['reason']);
    const r = await getRecord(ctx.params.id);
    if(r.status !== 'PENDING_APPROVAL') throw new HttpError(409, 'Hồ sơ không ở trạng thái chờ phê duyệt');
    r.status = 'REJECTED'; r.rejectedBy = user.username; r.rejectReason = str(ctx.body.reason, 500);
    push(r, user.username, 'REJECT', r.rejectReason);
    await docs.put('records', r.id, r);
    await log('RECORD_REJECT', user.username, {recordId: r.id, studentCode: r.studentCode});
    return {record: summary(r)};
  });

  router.post('/api/portal/records/:id/cancel', async ctx => {
    const user = await need(ctx, 'records.create');
    const r = await getRecord(ctx.params.id);
    if(r.createdBy !== user.username) throw new HttpError(403, 'Chỉ người lập hồ sơ mới được hủy');
    if(r.status !== 'PENDING_APPROVAL' && r.status !== 'REJECTED') throw new HttpError(409, 'Chỉ hủy được hồ sơ đang chờ duyệt hoặc bị từ chối');
    r.status = 'CANCELLED';
    push(r, user.username, 'CANCEL');
    await docs.put('records', r.id, r);
    await log('RECORD_CANCEL', user.username, {recordId: r.id});
    return {record: summary(r)};
  });

  router.post('/api/portal/records/:id/revoke', async ctx => {
    const user = await need(ctx, 'records.revoke');
    required(ctx.body, ['reason']);
    const r = await getRecord(ctx.params.id);
    if(r.status === 'APPROVED') {
      r.status = 'CANCELLED';
      push(r, user.username, 'CANCEL_BEFORE_CLAIM', str(ctx.body.reason, 500));
      await docs.put('records', r.id, r);
      await log('RECORD_CANCEL', user.username, {recordId: r.id, reason: str(ctx.body.reason, 500)});
      return {record: summary(r)};
    }
    if(r.status !== 'ISSUED') throw new HttpError(409, 'Chỉ thu hồi được văn bằng đã phát hành');
    await revokeRecord(r, user.username, str(ctx.body.reason, 500));
    return {record: summary(r), etag: d.statusRegistry.etag};
  });

  // ======================= KIEM TOAN / HE THONG =======================
  router.get('/api/portal/audit', async ctx => {
    await need(ctx, 'audit.read');
    const limit = Math.min(Number(ctx.url.searchParams.get('limit')) || 200, 500);
    return {items: await audit.listAudit(limit), total: await audit.auditCount()};
  });

  router.get('/api/portal/status-list', async ctx => {
    auth(ctx);
    const records = await docs.list<CredentialRecord>('records');
    return {
      url: d.statusUrl, etag: d.statusRegistry.etag, capacity: d.statusRegistry.list.length,
      allocated: d.statusRegistry.allocatedCount, revoked: records.filter(r => r.status === 'REVOKED').length,
      issuerDid: d.issuerDid, signingKey: d.issuerKeyPair.id, approverKey: d.approverKeyPair.id
    };
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

  router.post('/api/portal/users/:username/toggle', async ctx => {
    const user = await need(ctx, 'users.manage');
    const u = await docs.get('users', ctx.params.username);
    if(!u) throw new HttpError(404, 'Không tìm thấy tài khoản');
    if(u.username === user.username) throw new HttpError(400, 'Không thể tự khóa tài khoản của chính mình');
    u.active = !u.active;
    await docs.put('users', u.username, u);
    if(!u.active) sessions.destroyWhere(x => x.username === u.username);
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
    await docs.put('users', u.username, u);
    sessions.destroyWhere(x => x.username === u.username);
    await log('USER_RESET_PASSWORD', user.username, {username: u.username});
    return {ok: true};
  });

  // ======================= API CHO VI SINH VIEN (Bearer token) =======================
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
    return {token: signToken({sub: s.studentCode, method, aud: 'wallet'}, 2 * 3600), student: pubStudent(s), method};
  });

  function studentAuth(ctx: RouteCtx): string {
    const t = verifyToken<{sub: string; aud: string}>((ctx.req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if(!t || t.aud !== 'wallet') throw new HttpError(401, 'Token sinh viên không hợp lệ hoặc đã hết hạn', 'UNAUTHENTICATED');
    return t.sub;
  }

  router.get('/api/student/me', async ctx => {
    const code = studentAuth(ctx);
    const s = await getStudent(code);
    const records = (await docs.list<CredentialRecord>('records')).filter(r => r.studentCode === code && ['APPROVED', 'ISSUED', 'REVOKED', 'PENDING_APPROVAL'].includes(r.status))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(r => ({id: r.id, kind: r.kind, title: r.title, status: r.status, holderDid: r.holderDid, issuedAt: r.issuedAt, approvedAt: r.approvedAt,
        revokeReason: r.revokeReason, reissueOf: r.reissueOf, reissuedBy: r.reissuedBy}));
    return {student: pubStudent(s), records, issuerDid: d.issuerDid};
  });

  router.post('/api/student/nonce', async ctx => {
    const code = studentAuth(ctx);
    const c_nonce = randomBytes(24).toString('base64url');
    nonces.set(c_nonce, {studentCode: code, exp: Date.now() + 120_000});
    for(const [k, v] of nonces) if(v.exp < Date.now()) nonces.delete(k);
    return {c_nonce, expires_in: 120, aud: d.issuerDid};
  });

  // Nhan van bang (kieu OpenID4VCI): vi chung minh nam giu khoa rieng cua holder DID bang chu ky tren c_nonce
  router.post('/api/student/claim', async ctx => {
    const code = studentAuth(ctx);
    required(ctx.body, ['recordId', 'holderDid', 'c_nonce', 'proof']);
    const n = nonces.get(ctx.body.c_nonce);
    nonces.delete(ctx.body.c_nonce);
    if(!n || n.studentCode !== code || n.exp < Date.now()) throw new HttpError(400, 'c_nonce không hợp lệ hoặc đã hết hạn');
    const holderDid = String(ctx.body.holderDid);
    if(!/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(holderDid)) throw new HttpError(400, 'holderDid phải là did:key');
    const mb = holderDid.slice('did:key:'.length);
    let ok = false;
    try {
      const key = await EcdsaMultikey.from({'@context': 'https://w3id.org/security/multikey/v1', type: 'Multikey', id: `${holderDid}#${mb}`, controller: holderDid, publicKeyMultibase: mb});
      ok = await key.verifier().verify({data: new TextEncoder().encode(`openid4vci-proof|${ctx.body.c_nonce}|${d.issuerDid}`), signature: Buffer.from(String(ctx.body.proof), 'base64url')});
    } catch { ok = false; }
    if(!ok) throw new HttpError(401, 'Chữ ký chứng minh sở hữu khóa (proof of possession) không hợp lệ', 'BAD_PROOF');
    const r = await getRecord(String(ctx.body.recordId));
    if(r.studentCode !== code) throw new HttpError(403, 'Văn bằng này không thuộc về bạn');
    if(r.status === 'ISSUED') throw new HttpError(409, 'Văn bằng đã được nhận vào một ví khác. Nếu mất thiết bị, hãy gửi yêu cầu cấp lại');
    if(r.status !== 'APPROVED') throw new HttpError(409, 'Văn bằng chưa được phê duyệt để phát hành');
    const {index, credential} = await issueVc(r, holderDid);
    r.status = 'ISSUED'; r.issuedAt = now(); r.holderDid = holderDid; r.statusListIndex = index; r.credential = credential;
    push(r, `student:${code}`, 'CLAIM', `Ký phát hành vào ví ${holderDid.slice(0, 24)}…`);
    await docs.put('records', r.id, r);
    await log('CREDENTIAL_ISSUE', `student:${code}`, {recordId: r.id, statusListIndex: index});
    return {recordId: r.id, statusListIndex: index, credential};
  });

  router.post('/api/student/reissue', async ctx => {
    const code = studentAuth(ctx);
    required(ctx.body, ['recordId', 'reason']);
    const old = await getRecord(String(ctx.body.recordId));
    if(old.studentCode !== code) throw new HttpError(403, 'Văn bằng này không thuộc về bạn');
    if(old.status !== 'ISSUED' && old.status !== 'REVOKED') throw new HttpError(409, 'Chỉ yêu cầu cấp lại cho văn bằng đã phát hành');
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

  // Khoi phuc Bitstring Status List tu CSDL sau khi khoi dong lai container
  async function restoreStatus() {
    const records = await docs.list<CredentialRecord>('records');
    const indexes = records.filter(r => r.statusListIndex !== undefined);
    if(!indexes.length) return;
    const next = Math.max(...indexes.map(r => r.statusListIndex!)) + 1;
    await d.statusRegistry.restore(next, indexes.filter(r => r.status === 'REVOKED').map(r => r.statusListIndex!));
  }

  return {router, sessions, restoreStatus};
}

export type IssuerPortal = Awaited<ReturnType<typeof createIssuerPortal>>;
