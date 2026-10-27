import {createHash} from 'node:crypto';

export interface LegacyProvenancePayload {
  originalIssueDate: string;
  registryBookNumber: string;
  degreeSerial: string;
  sourceDocumentType: 'paper_ledger_scan';
  sourceDocumentDigest: string;
  verificationMethod: 'physical_ledger_reconciliation';
  verifiedBy: string;
  approvedBy: string;
  approvalTimestamp: string;
  approverDid: string;
  approverSignature?: string;
}

export function computeDocumentDigest(buffer: Buffer): string {
  return `urn:sha256:${createHash('sha256').update(buffer).digest('hex')}`;
}

export function canonicalizeProvenanceData(prov: Omit<LegacyProvenancePayload, 'approverSignature'>): Uint8Array {
  return new TextEncoder().encode([
    prov.originalIssueDate,
    prov.registryBookNumber,
    prov.degreeSerial,
    prov.sourceDocumentDigest,
    prov.verifiedBy,
    prov.approvedBy,
    prov.approvalTimestamp,
    prov.approverDid
  ].join('|'));
}

// Chu ky phe duyet ky bang Multikey P-256 cua Phong Dao tao (nam trong DID Document cua truong)
export async function signLegacyProvenance(
  provWithoutSig: Omit<LegacyProvenancePayload, 'approverSignature'>,
  approverKeyPair: any
): Promise<LegacyProvenancePayload> {
  const data = canonicalizeProvenanceData(provWithoutSig);
  const signatureBytes: Uint8Array = await approverKeyPair.signer().sign({data});
  return {...provWithoutSig, approverSignature: Buffer.from(signatureBytes).toString('base64url')};
}

export async function verifyLegacyProvenanceSignature(prov: LegacyProvenancePayload, approverPublicKeyMultikey: any): Promise<boolean> {
  if(!prov.approverSignature || !prov.approverDid) return false;
  const {approverSignature, ...rest} = prov;
  const data = canonicalizeProvenanceData(rest);
  const signature = new Uint8Array(Buffer.from(approverSignature, 'base64url'));
  return approverPublicKeyMultikey.verifier().verify({data, signature});
}
