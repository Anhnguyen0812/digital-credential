import {describe, it, expect, beforeAll} from 'vitest';
import {initializeIdentities, SystemIdentities} from '../src/crypto/multikey-manager.js';
import {createCustomDocumentLoader} from '../src/context/document-loader.js';
import {issueSelectiveDisclosureVc, deriveAndSignPresentation, verifyBoundPresentation} from '../src/crypto/holder-binding.js';
import {buildUnsignedDegreeVc, DEGREE_MANDATORY_POINTERS, LEGACY_DEGREE_MANDATORY_POINTERS, DEGREE_SELECTIVE_MAP} from '../src/profiles/degree-profile.js';
import {buildUnsignedCourseVc, COURSE_MANDATORY_POINTERS, COURSE_SELECTIVE_MAP} from '../src/profiles/course-profile.js';
import {computeDocumentDigest, signLegacyProvenance, verifyLegacyProvenanceSignature} from '../src/crypto/provenance-signer.js';
import {IssuerStatusRegistry} from '../src/status/status-store.js';

describe('Tuan 8: Holder Binding, CourseCertificate, Multikey Provenance & ETag Cache', () => {
  let ids: SystemIdentities;
  let documentLoader: any;
  const STATUS_URL = 'https://university.edu.vn/status/1';

  beforeAll(async () => {
    ids = await initializeIdentities();
    documentLoader = createCustomDocumentLoader(ids.registry);
  });

  async function degreeBase(index: number) {
    return issueSelectiveDisclosureVc({
      unsignedCredential: buildUnsignedDegreeVc({holderDid: ids.holderKeyPair.controller, statusListIndex: index, statusListUrl: STATUS_URL}),
      issuerKeyPair: ids.issuerKeyPair,
      mandatoryPointers: DEGREE_MANDATORY_POINTERS,
      documentLoader
    });
  }

  it('W4.1: Chan danh cap Derived VC (Attacker ky VP bang khoa cua minh)', async () => {
    const baseVc = await degreeBase(10);
    const {verifiablePresentation} = await deriveAndSignPresentation({
      baseCredential: baseVc, selectivePointers: [DEGREE_SELECTIVE_MAP.major],
      holderKeyPair: ids.attackerKeyPair, nonce: 'nonce-w4-1', audience: 'did:web:fpt.com.vn', documentLoader
    });
    const res = await verifyBoundPresentation({verifiablePresentation, expectedNonce: 'nonce-w4-1', expectedAudience: 'did:web:fpt.com.vn', documentLoader});
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('HOLDER_BINDING_MISMATCH');
  });

  it('W4.2: Chan gia danh vp.holder (sua holder thanh DID sinh vien nhung ky bang khoa Attacker)', async () => {
    const baseVc = await degreeBase(11);
    const {verifiablePresentation} = await deriveAndSignPresentation({
      baseCredential: baseVc, selectivePointers: [DEGREE_SELECTIVE_MAP.major],
      holderKeyPair: ids.attackerKeyPair, nonce: 'nonce-w4-2', audience: 'did:web:fpt.com.vn', documentLoader
    });
    verifiablePresentation.holder = ids.holderKeyPair.controller;
    const res = await verifyBoundPresentation({verifiablePresentation, expectedNonce: 'nonce-w4-2', expectedAudience: 'did:web:fpt.com.vn', documentLoader});
    expect(res.verified).toBe(false);
    expect(res.reason).toBe('CRYPTO_PROOF_OR_CHALLENGE_INVALID');
  });

  it('W4.3: Chan Cross-Verifier Replay (VP gui Verifier A bi dem sang Verifier B)', async () => {
    const baseVc = await degreeBase(12);
    const {verifiablePresentation} = await deriveAndSignPresentation({
      baseCredential: baseVc, selectivePointers: [DEGREE_SELECTIVE_MAP.major],
      holderKeyPair: ids.holderKeyPair, nonce: 'nonce-verifier-A', audience: 'did:web:verifier-A.vn', documentLoader
    });
    const okAtA = await verifyBoundPresentation({verifiablePresentation, expectedNonce: 'nonce-verifier-A', expectedAudience: 'did:web:verifier-A.vn', documentLoader});
    expect(okAtA.verified).toBe(true);
    const atB = await verifyBoundPresentation({verifiablePresentation, expectedNonce: 'nonce-verifier-A', expectedAudience: 'did:web:verifier-B.vn', documentLoader});
    expect(atB.verified).toBe(false);
  });

  it('W4.4: Cap phat, tiet lo chon loc va xac minh CourseCertificateCredential (an grade)', async () => {
    const baseCourseVc = await issueSelectiveDisclosureVc({
      unsignedCredential: buildUnsignedCourseVc({holderDid: ids.holderKeyPair.controller, statusListIndex: 2048, statusListUrl: STATUS_URL, validUntil: '2036-01-15T00:00:00Z'}),
      issuerKeyPair: ids.issuerKeyPair, mandatoryPointers: COURSE_MANDATORY_POINTERS, documentLoader
    });
    const {verifiablePresentation} = await deriveAndSignPresentation({
      baseCredential: baseCourseVc, selectivePointers: [COURSE_SELECTIVE_MAP.skills, COURSE_SELECTIVE_MAP.courseHours],
      holderKeyPair: ids.holderKeyPair, nonce: 'nonce-course-1', audience: 'did:web:viettel.com.vn', documentLoader
    });
    const res = await verifyBoundPresentation({verifiablePresentation, expectedNonce: 'nonce-course-1', expectedAudience: 'did:web:viettel.com.vn', documentLoader});
    expect(res.verified).toBe(true);
    expect(res.derivedVc.credentialSubject.courseName).toBe('An toàn và Bảo mật Hệ thống Thông tin');
    expect(res.derivedVc.credentialSubject.skills).toContain('W3C Verifiable Credentials');
    expect(res.derivedVc.credentialSubject.grade).toBeUndefined();
  });

  it('W4.5: Tu choi CourseCertificateCredential da qua han validUntil', async () => {
    const expired = await issueSelectiveDisclosureVc({
      unsignedCredential: buildUnsignedCourseVc({holderDid: ids.holderKeyPair.controller, statusListIndex: 2049, statusListUrl: STATUS_URL, validFrom: '2020-01-01T00:00:00Z', validUntil: '2021-01-01T00:00:00Z'}),
      issuerKeyPair: ids.issuerKeyPair, mandatoryPointers: COURSE_MANDATORY_POINTERS, documentLoader
    });
    const {verifiablePresentation} = await deriveAndSignPresentation({
      baseCredential: expired, selectivePointers: [COURSE_SELECTIVE_MAP.skills],
      holderKeyPair: ids.holderKeyPair, nonce: 'nonce-course-exp', audience: 'did:web:viettel.com.vn', documentLoader
    });
    const res = await verifyBoundPresentation({verifiablePresentation, expectedNonce: 'nonce-course-exp', expectedAudience: 'did:web:viettel.com.vn', documentLoader});
    expect(res.verified).toBe(false);
  });

  it('W4.6: Xac minh chu ky phe duyet so goc LegacyProvenance qua DID/Multikey', async () => {
    const digest = computeDocumentDigest(Buffer.from('Scan so goc nam 2015 UET-VNU'));
    const signedProv = await signLegacyProvenance({
      originalIssueDate: '2015-06-25', registryBookNumber: 'BK-2015/0842', degreeSerial: 'B15-004921',
      sourceDocumentType: 'paper_ledger_scan', sourceDocumentDigest: digest,
      verificationMethod: 'physical_ledger_reconciliation', verifiedBy: 'chuyenvien_daotao_01',
      approvedBy: 'truongphong_daotao_01', approvalTimestamp: '2026-10-01T08:30:00Z', approverDid: ids.approverKeyPair.id
    }, ids.approverKeyPair);

    const baseLegacy = await issueSelectiveDisclosureVc({
      unsignedCredential: buildUnsignedDegreeVc({holderDid: ids.holderKeyPair.controller, statusListIndex: 55, statusListUrl: STATUS_URL, legacyProvenance: signedProv}),
      issuerKeyPair: ids.issuerKeyPair, mandatoryPointers: LEGACY_DEGREE_MANDATORY_POINTERS, documentLoader
    });
    const {verifiablePresentation} = await deriveAndSignPresentation({
      baseCredential: baseLegacy, selectivePointers: [DEGREE_SELECTIVE_MAP.major],
      holderKeyPair: ids.holderKeyPair, nonce: 'nonce-legacy-multikey', audience: 'did:web:vng.com.vn', documentLoader
    });
    const res = await verifyBoundPresentation({verifiablePresentation, expectedNonce: 'nonce-legacy-multikey', expectedAudience: 'did:web:vng.com.vn', documentLoader});
    expect(res.verified).toBe(true);
    const prov = res.derivedVc.credentialSubject.legacyProvenance;
    expect(prov.registryBookNumber).toBe('BK-2015/0842');
    const approverDoc = await documentLoader(prov.approverDid);
    expect(approverDoc.document.id).toBe(ids.approverKeyPair.id);
    expect(await verifyLegacyProvenanceSignature(prov, ids.approverKeyPair)).toBe(true);
    // Sua so hieu so goc -> chu ky phe duyet khong con hop le
    expect(await verifyLegacyProvenanceSignature({...prov, registryBookNumber: 'BK-2015/0999'}, ids.approverKeyPair)).toBe(false);
  });

  it('W4.7: ETag Revalidation tren BitstringStatusList: 304 khi chua thu hoi, 200 khi vua thu hoi', async () => {
    const reg = new IssuerStatusRegistry('https://university.edu.vn/status/degree-list-1', ids.issuerKeyPair, documentLoader);
    const res1 = await reg.handleHttpGet();
    expect(res1.status).toBe(200);
    expect(res1.etag).toMatch(/^W\/"/);
    const res2 = await reg.handleHttpGet(res1.etag);
    expect(res2.status).toBe(304);
    expect(res2.body).toBeUndefined();
    await reg.setRevoked(8321, true);
    const res3 = await reg.handleHttpGet(res1.etag);
    expect(res3.status).toBe(200);
    expect(res3.etag).not.toBe(res1.etag);
  });
});
