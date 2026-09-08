export const ISSUER_ID = 'https://university.example/issuers/it-department';
export const KEY_ID = ISSUER_ID + '#key-1';
export const DEGREE_CONTEXT = 'https://university.example/contexts/degree-v1';
export const STATUS_URL = 'https://university.example/status/degree-list-1';
export const VERIFY_AUDIENCE = 'https://employer.example/verify';

export const degreeContextDocument = {
  '@context': {
    '@protected': true,
    DegreeCredential: 'https://university.example/vocab#DegreeCredential',
    studentName: 'https://university.example/vocab#studentName',
    studentCode: 'https://university.example/vocab#studentCode',
    degreeName: 'https://university.example/vocab#degreeName',
    major: 'https://university.example/vocab#major',
    graduationDate: {
      '@id': 'https://university.example/vocab#graduationDate',
      '@type': 'http://www.w3.org/2001/XMLSchema#date'
    },
    gpa: {
      '@id': 'https://university.example/vocab#gpa',
      '@type': 'http://www.w3.org/2001/XMLSchema#decimal'
    },
    classification: 'https://university.example/vocab#classification',
    graduated: {
      '@id': 'https://university.example/vocab#graduated',
      '@type': 'http://www.w3.org/2001/XMLSchema#boolean'
    },
    SimpleStatusEntry: 'https://university.example/vocab#SimpleStatusEntry',
    myStatusIndex: 'https://university.example/vocab#myStatusIndex',
    myStatusPurpose: 'https://university.example/vocab#myStatusPurpose',
    myStatusUrl: {
      '@id': 'https://university.example/vocab#myStatusUrl',
      '@type': '@id'
    }
  }
};
