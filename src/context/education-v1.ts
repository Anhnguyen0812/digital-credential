export const EDUCATION_CONTEXT_URL = 'https://university.edu.vn/contexts/education-v1.jsonld';

// Claim dong cho benchmark mo rong (claim_0 .. claim_199). Neu khong khai bao tuong minh,
// RDFC-1.0 se bao loi / loai bo thuoc tinh truoc khi ky.
const extraClaimTerms: Record<string, string> = {};
for(let i = 0; i < 200; i++) extraClaimTerms[`claim_${i}`] = `edu:claim_${i}`;

export const EDUCATION_CONTEXT_DOC = {
  '@context': {
    '@protected': true,
    xsd: 'http://www.w3.org/2001/XMLSchema#',
    edu: 'https://university.edu.vn/vocab#',

    // Credential types
    DegreeCredential: 'edu:DegreeCredential',
    LegacyReissuedCredential: 'edu:LegacyReissuedCredential',
    CourseCertificateCredential: 'edu:CourseCertificateCredential',
    LegacyProvenance: 'edu:LegacyProvenance',

    // Common & degree claims
    studentName: 'edu:studentName',
    studentCode: 'edu:studentCode',
    major: 'edu:major',
    degreeName: 'edu:degreeName',
    graduationDate: {'@id': 'edu:graduationDate', '@type': 'xsd:string'},
    graduated: {'@id': 'edu:graduated', '@type': 'xsd:boolean'},
    gpa: 'edu:gpa',
    classification: 'edu:classification',

    // Course certificate claims
    courseCode: 'edu:courseCode',
    courseName: 'edu:courseName',
    courseHours: {'@id': 'edu:courseHours', '@type': 'xsd:integer'},
    completionDate: {'@id': 'edu:completionDate', '@type': 'xsd:string'},
    grade: 'edu:grade',
    skills: {'@id': 'edu:skills', '@container': '@set'},
    certificateValid: {'@id': 'edu:certificateValid', '@type': 'xsd:boolean'},

    // Legacy provenance
    legacyProvenance: {
      '@id': 'edu:legacyProvenance',
      '@context': {
        '@protected': true,
        originalIssueDate: 'edu:originalIssueDate',
        registryBookNumber: 'edu:registryBookNumber',
        degreeSerial: 'edu:degreeSerial',
        sourceDocumentType: 'edu:sourceDocumentType',
        sourceDocumentDigest: 'edu:sourceDocumentDigest',
        verificationMethod: 'edu:verificationMethod',
        verifiedBy: 'edu:verifiedBy',
        approvedBy: 'edu:approvedBy',
        approvalTimestamp: 'edu:approvalTimestamp',
        approverDid: 'edu:approverDid',
        approverSignature: 'edu:approverSignature'
      }
    },

    // Claim dong cho benchmark
    extraClaims: {
      '@id': 'edu:extraClaims',
      '@context': {'@protected': true, ...extraClaimTerms}
    }
  }
};
