import {EDUCATION_CONTEXT_URL} from '../context/education-v1.js';
import type {LegacyProvenancePayload} from '../crypto/provenance-signer.js';

export const DEGREE_MANDATORY_POINTERS = [
  '/issuer',
  '/validFrom',
  '/credentialStatus',
  '/credentialSubject/id',
  '/credentialSubject/studentName',
  '/credentialSubject/graduated'
];

export const LEGACY_DEGREE_MANDATORY_POINTERS = [
  ...DEGREE_MANDATORY_POINTERS,
  '/credentialSubject/legacyProvenance'
];

export const DEGREE_SELECTIVE_MAP: Record<string, string> = {
  studentCode: '/credentialSubject/studentCode',
  major: '/credentialSubject/major',
  degreeName: '/credentialSubject/degreeName',
  graduationDate: '/credentialSubject/graduationDate',
  gpa: '/credentialSubject/gpa',
  classification: '/credentialSubject/classification'
};

export const DEGREE_DEFAULT_SUBJECT = {
  studentName: 'Nguyễn Phi Anh',
  studentCode: '23020009',
  major: 'Công nghệ thông tin',
  degreeName: 'Cử nhân Công nghệ thông tin',
  graduationDate: '2026-06-30',
  graduated: true,
  gpa: '3.65',
  classification: 'Xuất sắc'
};

export function buildUnsignedDegreeVc(params: {
  holderDid: string;
  statusListIndex: number;
  statusListUrl: string;
  issuerDid?: string;
  legacyProvenance?: LegacyProvenancePayload;
  subject?: Partial<typeof DEGREE_DEFAULT_SUBJECT>;
}) {
  const types = ['VerifiableCredential', 'DegreeCredential'];
  if(params.legacyProvenance) types.push('LegacyReissuedCredential');
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', EDUCATION_CONTEXT_URL],
    type: types,
    issuer: params.issuerDid ?? 'did:web:university.edu.vn',
    validFrom: '2026-10-01T00:00:00Z',
    credentialStatus: {
      id: `${params.statusListUrl}#${params.statusListIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(params.statusListIndex),
      statusListCredential: params.statusListUrl
    },
    credentialSubject: {
      id: params.holderDid,
      ...DEGREE_DEFAULT_SUBJECT,
      ...(params.subject ?? {}),
      ...(params.legacyProvenance ? {legacyProvenance: params.legacyProvenance} : {})
    }
  };
}
