import {statusEntry} from '../status/status-store.js';
import {EDUCATION_CONTEXT_URL} from '../context/education-v1.js';

export const COURSE_MANDATORY_POINTERS = [
  '/issuer',
  '/validFrom',
  '/validUntil',
  '/credentialStatus',
  '/credentialSubject/id',
  '/credentialSubject/studentName',
  '/credentialSubject/courseName',
  '/credentialSubject/certificateValid'
];

export const COURSE_SELECTIVE_MAP: Record<string, string> = {
  courseCode: '/credentialSubject/courseCode',
  courseHours: '/credentialSubject/courseHours',
  completionDate: '/credentialSubject/completionDate',
  grade: '/credentialSubject/grade',
  skills: '/credentialSubject/skills'
};

export function buildUnsignedCourseVc(params: {
  holderDid: string;
  statusListIndex: number;
  statusListUrl: string;
  suspensionListUrl?: string;
  issuerDid?: string;
  validFrom?: string;
  validUntil?: string;
  subject?: Record<string, any>;
}) {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', EDUCATION_CONTEXT_URL],
    type: ['VerifiableCredential', 'CourseCertificateCredential'],
    issuer: params.issuerDid ?? 'did:web:university.edu.vn',
    validFrom: params.validFrom ?? '2026-01-15T00:00:00Z',
    validUntil: params.validUntil ?? '2028-01-15T00:00:00Z',
    credentialStatus: params.suspensionListUrl ? [
      statusEntry(params.statusListUrl, params.statusListIndex, 'revocation'),
      statusEntry(params.suspensionListUrl, params.statusListIndex, 'suspension')
    ] : statusEntry(params.statusListUrl, params.statusListIndex, 'revocation'),
    credentialSubject: {
      studentName: 'Nguyễn Phi Anh',
      courseCode: 'INT3306',
      courseName: 'An toàn và Bảo mật Hệ thống Thông tin',
      courseHours: 45,
      completionDate: '2026-01-10',
      grade: 'A+',
      skills: ['W3C Verifiable Credentials', 'Applied Cryptography', 'Zero Trust'],
      certificateValid: true,
      ...(params.subject ?? {}),
      id: params.holderDid
    }
  };
}
