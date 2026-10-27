import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import type {LegacyProvenance} from './types.js';

export function createOrGetSampleScanFile(filePath: string, sizeBytes: number = 2_400_000): string {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, {recursive: true});
  }

  if (!fs.existsSync(filePath) || fs.statSync(filePath).size !== sizeBytes) {
    // Tao file scan mau voi kich thuoc thuc te 2.4 MB (2,400,000 bytes)
    const header = Buffer.from('%PDF-1.4\n%SO_GOC_LUU_TRU_DAI_HOC_2015\n');
    const chunk = Buffer.alloc(sizeBytes - header.length, 0x5a); // 0x5a = 'Z'
    const fullBuffer = Buffer.concat([header, chunk]);
    fs.writeFileSync(filePath, fullBuffer);
  }

  return filePath;
}

export function computeFileDigest(filePath: string): string {
  const buffer = fs.readFileSync(filePath);
  const hash = crypto.createHash('sha256').update(buffer).digest('hex');
  return `urn:sha256:${hash}`;
}

export function generateApproverKeyPair() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: {type: 'spki', format: 'pem'},
    privateKeyEncoding: {type: 'pkcs8', format: 'pem'}
  });
}

export function makeApprovalMessage(payload: {
  studentCode: string;
  registryBookNumber: string;
  originalIssueDate: string;
  sourceDocumentDigest: string;
}): string {
  return `${payload.studentCode}|${payload.registryBookNumber}|${payload.originalIssueDate}|${payload.sourceDocumentDigest}`;
}

export function signApproverAction(
  payload: {
    studentCode: string;
    registryBookNumber: string;
    originalIssueDate: string;
    sourceDocumentDigest: string;
  },
  privateKeyPem: string
): string {
  const msg = makeApprovalMessage(payload);
  const signer = crypto.createSign('SHA256');
  signer.update(msg);
  signer.end();
  return signer.sign(privateKeyPem, 'base64');
}

export function verifyApproverSignature(
  payload: {
    studentCode: string;
    registryBookNumber: string;
    originalIssueDate: string;
    sourceDocumentDigest: string;
  },
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  try {
    const msg = makeApprovalMessage(payload);
    const verifier = crypto.createVerify('SHA256');
    verifier.update(msg);
    verifier.end();
    return verifier.verify(publicKeyPem, signatureBase64, 'base64');
  } catch {
    return false;
  }
}

export function buildLegacyProvenance(params: {
  scanFilePath: string;
  studentCode: string;
  registryBookNumber: string;
  originalIssueDate: string;
  degreeSerial: string;
  verifiedBy: string;
  approvedBy: string;
  approverPrivateKeyPem: string;
}): LegacyProvenance {
  const digest = computeFileDigest(params.scanFilePath);
  const approvalSig = signApproverAction({
    studentCode: params.studentCode,
    registryBookNumber: params.registryBookNumber,
    originalIssueDate: params.originalIssueDate,
    sourceDocumentDigest: digest
  }, params.approverPrivateKeyPem);

  return {
    originalIssueDate: params.originalIssueDate,
    registryBookNumber: params.registryBookNumber,
    degreeSerial: params.degreeSerial,
    sourceDocumentType: 'paper_ledger_scan',
    sourceDocumentDigest: digest,
    reconciliationMethod: 'physical_ledger_reconciliation',
    verifiedBy: params.verifiedBy,
    approvedBy: params.approvedBy,
    approvalTimestamp: new Date().toISOString(),
    approverSignature: approvalSig
  };
}
