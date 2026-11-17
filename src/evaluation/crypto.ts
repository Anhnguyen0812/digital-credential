import assert from 'node:assert/strict';
import * as vc from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as rdfc} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {createVerifyCryptosuite as sdVerifier} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {createCustomDocumentLoader} from '../context/document-loader.js';
import {deriveVc, issueFullDisclosureVc, issueSelectiveDisclosureVc,
  signPresentationWithHolder, verifyBoundPresentation} from '../crypto/holder-binding.js';
import {initializeIdentities} from '../crypto/multikey-manager.js';
import {computeDocumentDigest, signLegacyProvenance} from '../crypto/provenance-signer.js';
import {buildUnsignedCourseVc, COURSE_MANDATORY_POINTERS, COURSE_SELECTIVE_MAP} from '../profiles/course-profile.js';
import {buildUnsignedDegreeVc, DEGREE_MANDATORY_POINTERS, DEGREE_SELECTIVE_MAP,
  LEGACY_DEGREE_MANDATORY_POINTERS} from '../profiles/degree-profile.js';
import {checkPresentationProfile} from '../profiles/presentation-policy.js';
import {bytes, count, startRun, timed} from './run.js';

const audience = 'redirect_uri:https://verifier.example/direct-post';
const cases = [
  {name: 'recruitment', profile: 'DegreeCredential', requested: ['major'], required: ['studentName', 'graduated']},
  {name: 'scholarship', profile: 'DegreeCredential', requested: ['major', 'gpa'], required: ['studentName', 'graduated']},
  {name: 'course', profile: 'CourseCertificateCredential', requested: ['skills'],
    required: ['studentName', 'courseName', 'certificateValid']},
  {name: 'legacy', profile: 'DegreeCredential', requested: ['degreeName'], required: ['studentName', 'graduated']}
] as const;

function businessKeys(credential: any): string[] {
  return Object.keys(credential.credentialSubject).filter(key => key !== 'id' && key !== 'legacyProvenance').sort();
}

export async function evaluateCrypto() {
  const iterations = count('BENCH_ITER', 100);
  const warmup = count('BENCH_WARMUP', 10, 0);
  const session = count('BENCH_SESSION', 1);
  const fixturesPerCase = 25;
  const run = startRun('crypto', {iterations, warmup, session, fixturesPerCase, cases, audience,
    status: 'always-valid stub for both modes', timeUnit: 'ms', sizeUnit: 'UTF-8 JSON bytes',
    order: 'alternate by session, case and round'});
  const {issuerKeyPair, holderKeyPair, approverKeyPair, registry} = await initializeIdentities('did:web:issuer.example');
  const documentLoader = createCustomDocumentLoader(registry);
  let failures = 0;

  for(const [caseIndex, scenario] of cases.entries()) {
    const isCourse = scenario.profile === 'CourseCertificateCredential';
    const fixtures = await Promise.all(Array.from({length: fixturesPerCase}, async (_, i) => {
      const common = {
        holderDid: holderKeyPair.controller, issuerDid: issuerKeyPair.controller,
        statusListIndex: caseIndex * fixturesPerCase + i,
        statusListUrl: 'https://issuer.example/status/revocation',
        suspensionListUrl: 'https://issuer.example/status/suspension'
      };
      const studentName = `${['Sinh Viên Mẫu', 'Học Viên Tổng Hợp', 'Người Học Dữ Liệu Thử Nghiệm'][i % 3]} ${i + 1}`;
      if(isCourse) {
        return buildUnsignedCourseVc({...common, validFrom: '2025-01-01T00:00:00Z', validUntil: '2099-01-01T00:00:00Z',
          subject: {studentName, courseCode: `TEST-${i}`, courseName: 'Học phần thử nghiệm',
            courseHours: 30 + i, completionDate: '2025-01-02', grade: ['A', 'B', 'C'][i % 3],
            skills: ['Kỹ năng mẫu 1', 'Kỹ năng mẫu 2', 'Kỹ năng mẫu 3'].slice(0, 1 + i % 3), certificateValid: true}});
      }
      const legacyProvenance = scenario.name === 'legacy' ? await signLegacyProvenance({
        originalIssueDate: '2020-06-30', registryBookNumber: `TEST-BOOK-${i}`, degreeSerial: `TEST-SERIAL-${i}`,
        sourceDocumentType: 'paper_ledger_scan', sourceDocumentDigest: computeDocumentDigest(Buffer.from(`synthetic-ledger-${i}`)),
        verificationMethod: 'physical_ledger_reconciliation', verifiedBy: 'Registrar Test', approvedBy: 'Approver Test',
        approvalTimestamp: '2025-02-01T00:00:00Z', approverDid: approverKeyPair.id
      }, approverKeyPair) : undefined;
      return {...buildUnsignedDegreeVc({...common, legacyProvenance, subject: {
        studentName, studentCode: `TEST-STUDENT-${i}`, major: ['Ngành thử nghiệm A', 'Ngành thử nghiệm B'][i % 2],
        degreeName: 'Văn bằng tổng hợp', graduationDate: '2025-01-01',
        graduated: true, gpa: (2.5 + i / 20).toFixed(2), classification: ['Khá', 'Giỏi'][i % 2]
      }}), validFrom: '2025-01-01T00:00:00Z'};
    }));
    const mandatoryPointers = isCourse ? COURSE_MANDATORY_POINTERS :
      scenario.name === 'legacy' ? LEGACY_DEGREE_MANDATORY_POINTERS : DEGREE_MANDATORY_POINTERS;
    const approved = [...scenario.requested];
    const maps = isCourse ? COURSE_SELECTIVE_MAP : DEGREE_SELECTIVE_MAP;
    const selectivePointers = approved.map(key => maps[key]);

    for(let round = -warmup; round < iterations; round++) {
      const fixture = Math.max(0, round) % fixturesPerCase;
      const unsignedCredential = fixtures[fixture];
      const order = (round + session + caseIndex) % 2 ? ['sd', 'full'] : ['full', 'sd'];
      for(const [position, mode] of order.entries()) {
        const sample = {scenario: scenario.name, profile: scenario.profile, session, round, fixture, mode, position,
          mandatoryPointers, requested: scenario.requested, approved};
        try {
          const inputs = {unsignedCredential, issuerKeyPair, documentLoader};
          const sd = mode === 'sd';
          const [base, issueMs] = await timed(() => sd
            ? issueSelectiveDisclosureVc({...inputs, mandatoryPointers})
            : issueFullDisclosureVc(inputs));
          const [credential, deriveMs] = sd
            ? await timed(() => deriveVc({baseCredential: base, selectivePointers, documentLoader}))
            : [base, null];
          const nonce = `bench-${session}-${scenario.name}-${round}`;
          const [vp, holderSignMs] = await timed(() => signPresentationWithHolder({
            derivedVc: credential, holderKeyPair, nonce, audience, documentLoader
          }));
          const [vcResult, verifyVcMs] = await timed<{verified: boolean}>(() => vc.verifyCredential({
            credential, documentLoader, suite: new DataIntegrityProof({cryptosuite: sd ? sdVerifier() : rdfc}),
            checkStatus: async () => ({verified: true})
          }));
          const [vpResult, verifyVpMs] = await timed(() => verifyBoundPresentation({
            verifiablePresentation: vp, expectedNonce: nonce, expectedAudience: audience, documentLoader
          }));
          const sent = vp.verifiableCredential[0];
          const total = businessKeys(unsignedCredential);
          const disclosed = businessKeys(sent);
          const expected = sd ? [...scenario.required, ...approved].sort() : total;
          assert.deepEqual(disclosed, expected);
          assert.equal(sent.credentialSubject.id, unsignedCredential.credentialSubject.id);
          assert.deepEqual(sent.credentialStatus, unsignedCredential.credentialStatus);
          const sourceSubject = unsignedCredential.credentialSubject;
          assert.deepEqual(sent.credentialSubject.legacyProvenance,
            'legacyProvenance' in sourceSubject ? sourceSubject.legacyProvenance : undefined);
          if(sd) assert.equal(checkPresentationProfile(sent, scenario.profile, approved), null);
          assert.ok(vcResult.verified && vpResult.verified, vpResult.reason ?? 'VC verification failed');
          run.sample({...sample, ok: true, issueMs, deriveMs, holderSignMs, verifyVcMs, verifyVpMs,
            total, disclosed, hidden: total.filter(key => !disclosed.includes(key)),
            visibleMetadata: {credential: Object.keys(sent).filter(key => key !== 'credentialSubject'),
              subjectId: Boolean(sent.credentialSubject.id), legacyProvenance: Object.keys(sent.credentialSubject.legacyProvenance ?? {}),
              statusPurposes: sent.credentialStatus.map((entry: any) => entry.statusPurpose), holder: Boolean(vp.holder)},
            baseBytes: bytes(base), vcBytes: bytes(sent), vpBytes: bytes(vp),
            vcProofBytes: bytes(sent.proof), vpProofBytes: bytes(vp.proof)});
        } catch(error) {
          failures++;
          run.sample({...sample, ok: false, error: error instanceof Error ? error.message : String(error)});
        }
      }
    }
  }
  run.finish();
  assert.equal(failures, 0, 'See failed samples in samples.jsonl');
}
