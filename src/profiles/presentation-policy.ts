import {DEGREE_SELECTIVE_MAP} from './degree-profile.js';
import {COURSE_SELECTIVE_MAP} from './course-profile.js';

export const PRESENTATION_PROFILES = {
  DegreeCredential: {required: ['studentName', 'graduated'], optional: Object.keys(DEGREE_SELECTIVE_MAP)},
  CourseCertificateCredential: {required: ['studentName', 'courseName', 'certificateValid'], optional: Object.keys(COURSE_SELECTIVE_MAP)}
};
export type CredentialProfile = keyof typeof PRESENTATION_PROFILES;

const nonempty = (x: unknown) => typeof x === 'string' && x.trim().length > 0;
const date = (x: unknown) => typeof x === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(x) && Number.isFinite(Date.parse(x));

function validClaim(key: string, value: unknown): boolean {
  switch(key) {
    case 'graduated':
    case 'certificateValid':
      return value === true;
    case 'courseHours':
      return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
    case 'gpa':
      return (typeof value === 'number' || (typeof value === 'string' && /^\d+(\.\d+)?$/.test(value))) &&
        Number(value) >= 0 && Number(value) <= 4;
    case 'graduationDate':
    case 'completionDate':
      return date(value);
    case 'skills':
      return Array.isArray(value) && value.length > 0 && value.every(nonempty);
    default:
      return nonempty(value);
  }
}

export function checkPresentationProfile(credential: any, profile: CredentialProfile, wanted: string[]) {
  const {required, optional} = PRESENTATION_PROFILES[profile];
  const types = credential.type;
  if(!Array.isArray(types) || !types.includes('VerifiableCredential') || !types.includes(profile) ||
    Object.keys(PRESENTATION_PROFILES).some(type => type !== profile && types.includes(type))) {
    return 'Loại văn bằng không khớp yêu cầu';
  }
  const subject = credential.credentialSubject;
  if(!subject || Array.isArray(subject) || typeof subject !== 'object') return 'Chủ thể không hợp lệ';
  if(types.includes('LegacyReissuedCredential') !== Boolean(subject.legacyProvenance) ||
    (subject.legacyProvenance && profile !== 'DegreeCredential')) return 'Provenance không khớp loại văn bằng';
  for(const key of new Set([...required, ...wanted])) {
    if(!Object.hasOwn(subject, key) || !validClaim(key, subject[key])) return 'Thuộc tính thiếu hoặc không hợp lệ: ' + key;
  }
  const allowed = new Set(['id', ...required, ...wanted, 'legacyProvenance']);
  if(Object.keys(subject).some(key => !allowed.has(key))) return 'Có thuộc tính ngoài yêu cầu';
  return null;
}
