import * as path from 'node:path';
import * as fs from 'node:fs';
import {beforeAll, describe, expect, test} from 'vitest';
import {makeIssuerSetup} from '../src/issuer-setup.js';
import {
  issueLegacyDegree,
  discloseLegacyDegree,
  verifyBaseDegree,
  verifyDegree
} from '../src/credential-service.js';
import {StatusStore} from '../src/status-store.js';
import {
  createOrGetSampleScanFile,
  computeFileDigest,
  generateApproverKeyPair,
  buildLegacyProvenance,
  verifyApproverSignature
} from '../src/legacy-service.js';
import type {DegreeInput} from '../src/types.js';

let setup: any;
let approverKeys: any;
let scanFilePath: string;
let legacyInput: DegreeInput;
let signedLegacyVc: any;
let disclosedLegacyVc: any;

beforeAll(async () => {
  setup = await makeIssuerSetup();
  approverKeys = generateApproverKeyPair();

  const testVectorsDir = path.resolve(process.cwd(), 'test-vectors');
  scanFilePath = path.join(testVectorsDir, 'sample_ledger_2015.bin');
  createOrGetSampleScanFile(scanFilePath, 2_400_000); // 2.4 MB scan file

  const provenance = buildLegacyProvenance({
    scanFilePath,
    studentCode: '23020009',
    registryBookNumber: 'BK-2015/0842',
    originalIssueDate: '2015-06-25',
    degreeSerial: 'B15-004921',
    verifiedBy: 'nv_daotao_01',
    approvedBy: 'truongphong_daotao_01',
    approverPrivateKeyPem: approverKeys.privateKey
  });

  legacyInput = {
    id: 'urn:uuid:legacy-degree-2015-0842',
    statusIndex: 42,
    subject: {
      id: 'did:key:z6MkuLearnerWalletKey2026',
      studentName: 'Nguyễn Phi Anh',
      studentCode: '23020009',
      degreeName: 'Cử nhân Công nghệ thông tin',
      major: 'Công nghệ thông tin',
      graduationDate: '2015-06-25',
      gpa: 3.65,
      classification: 'Xuất sắc',
      graduated: true,
      legacyProvenance: provenance
    }
  };

  signedLegacyVc = await issueLegacyDegree(legacyInput, setup);
  disclosedLegacyVc = await discloseLegacyDegree(signedLegacyVc, setup);
});

describe('Legacy Ingestion & Cryptographic Provenance (Week 06)', () => {
  test('T1 - Issue va verify base credential co LegacyProvenance hop le', async () => {
    const store = new StatusStore();
    const result = await verifyBaseDegree(signedLegacyVc, setup, store);
    expect(result.verified).toBe(true);
    expect(result.cryptoVerified).toBe(true);

    const prov = signedLegacyVc.credentialSubject.legacyProvenance;
    expect(prov).toBeDefined();
    expect(prov.registryBookNumber).toBe('BK-2015/0842');
    expect(prov.sourceDocumentDigest).toMatch(/^urn:sha256:[a-f0-9]{64}$/);

    // Kiem tra chu ky phe duyet cua lanh dao phong dao tao
    const approverValid = verifyApproverSignature({
      studentCode: '23020009',
      registryBookNumber: prov.registryBookNumber,
      originalIssueDate: prov.originalIssueDate,
      sourceDocumentDigest: prov.sourceDocumentDigest
    }, prov.approverSignature, approverKeys.publicKey);
    expect(approverValid).toBe(true);
  });

  test('T2 - Tamper so vao so hoac ngay cap thi Data Integrity Proof that bai', async () => {
    const tampered = structuredClone(signedLegacyVc);
    tampered.credentialSubject.legacyProvenance.registryBookNumber = 'BK-2015/0999';

    const store = new StatusStore();
    const result = await verifyBaseDegree(tampered, setup, store);
    expect(result.verified).toBe(false);
    expect(result.cryptoVerified).toBe(false);
  });

  test('T3 - Trao doi file scan thi hash digest mismatch va chu ky approver sai', async () => {
    // Tao mot file scan gia mao khac
    const fakeScanPath = path.join(path.dirname(scanFilePath), 'fake_ledger.bin');
    fs.writeFileSync(fakeScanPath, Buffer.from('FAKE SCAN CONTENT MODIFIED'));
    const fakeDigest = computeFileDigest(fakeScanPath);
    try { fs.unlinkSync(fakeScanPath); } catch {}

    const prov = signedLegacyVc.credentialSubject.legacyProvenance;
    expect(fakeDigest).not.toBe(prov.sourceDocumentDigest);

    // Chu ky phe duyet khong hop le neu digest bi thay doi
    const approverValid = verifyApproverSignature({
      studentCode: '23020009',
      registryBookNumber: prov.registryBookNumber,
      originalIssueDate: prov.originalIssueDate,
      sourceDocumentDigest: fakeDigest
    }, prov.approverSignature, approverKeys.publicKey);
    expect(approverValid).toBe(false);
  });

  test('T4 - Selective disclosure an GPA va studentCode nhung giu nguyen provenance', async () => {
    const subj = disclosedLegacyVc.credentialSubject;
    expect(subj.studentName).toBe('Nguyễn Phi Anh');
    expect(subj.major).toBe('Công nghệ thông tin');
    expect(subj.graduated).toBe(true);
    expect(subj.legacyProvenance).toBeDefined();
    expect(subj.legacyProvenance.registryBookNumber).toBe('BK-2015/0842');

    // GPA va studentCode da duoc an
    expect(subj.gpa).toBeUndefined();
    expect(subj.studentCode).toBeUndefined();
    expect(subj.classification).toBeUndefined();

    const store = new StatusStore();
    const result = await verifyDegree(disclosedLegacyVc, setup, store);
    expect(result.verified).toBe(true);
    expect(result.cryptoVerified).toBe(true);
  });
});
