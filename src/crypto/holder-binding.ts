import {randomUUID} from 'node:crypto';
import * as vc from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  createSignCryptosuite as createSdSignSuite,
  createDiscloseCryptosuite,
  createVerifyCryptosuite as createSdVerifySuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {cryptosuite as rdfcCryptosuite} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';

// 1. Issuer ky Base VC bang ecdsa-sd-2023
export async function issueSelectiveDisclosureVc(params: {
  unsignedCredential: any;
  issuerKeyPair: any;
  mandatoryPointers: string[];
  documentLoader: any;
}): Promise<any> {
  const suite = new DataIntegrityProof({
    signer: params.issuerKeyPair.signer(),
    cryptosuite: createSdSignSuite({mandatoryPointers: params.mandatoryPointers})
  });
  suite.proof = {id: 'urn:uuid:' + randomUUID()};
  return vc.issue({
    credential: structuredClone(params.unsignedCredential),
    suite,
    documentLoader: params.documentLoader
  });
}

// Baseline (TSK-02): VC ky ecdsa-rdfc-2019, tiet lo 100% du lieu
export async function issueFullDisclosureVc(params: {
  unsignedCredential: any;
  issuerKeyPair: any;
  documentLoader: any;
}): Promise<any> {
  const suite = new DataIntegrityProof({
    signer: params.issuerKeyPair.signer(),
    cryptosuite: rdfcCryptosuite
  });
  return vc.issue({
    credential: structuredClone(params.unsignedCredential),
    suite,
    documentLoader: params.documentLoader
  });
}

export async function deriveVc(params: {baseCredential: any; selectivePointers: string[]; documentLoader: any}) {
  const suite = new DataIntegrityProof({
    cryptosuite: createDiscloseCryptosuite({
      proofId: params.baseCredential?.proof?.id,
      selectivePointers: params.selectivePointers
    })
  });
  return vc.derive({
    verifiableCredential: params.baseCredential,
    suite,
    documentLoader: params.documentLoader
  });
}

// Ky VerifiablePresentation bang khoa cua Holder (Proof of Possession) tren (challenge=nonce, domain=audience)
export async function signPresentationWithHolder(params: {
  derivedVc: any;
  holderKeyPair: any;
  nonce: string;
  audience: string;
  documentLoader: any;
}) {
  const unsignedVp = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    holder: params.holderKeyPair.controller,
    verifiableCredential: [params.derivedVc]
  };
  const holderSuite = new DataIntegrityProof({
    signer: params.holderKeyPair.signer(),
    cryptosuite: rdfcCryptosuite
  });
  return vc.signPresentation({
    presentation: unsignedVp,
    suite: holderSuite,
    challenge: params.nonce,
    domain: params.audience,
    documentLoader: params.documentLoader
  });
}

// 2. Holder tao Derived VC (an claim khong chon) + ky VP (Holder Binding)
export async function deriveAndSignPresentation(params: {
  baseCredential: any;
  selectivePointers: string[];
  holderKeyPair: any;
  nonce: string;
  audience: string;
  documentLoader: any;
}): Promise<{derivedVc: any; verifiablePresentation: any}> {
  const derivedVc = await deriveVc(params);
  const verifiablePresentation = await signPresentationWithHolder({...params, derivedVc});
  return {derivedVc, verifiablePresentation};
}

export type BoundVerifyResult = {verified: boolean; reason?: string; derivedVc?: any; detail?: any};

// 3a. Rang buoc dinh danh: vp.holder phai trung credentialSubject.id
export function checkHolderIdentity(vp: any): BoundVerifyResult {
  const derivedVc = Array.isArray(vp?.verifiableCredential) ? vp.verifiableCredential[0] : vp?.verifiableCredential;
  if(!derivedVc) return {verified: false, reason: 'MISSING_CREDENTIAL_IN_VP'};
  const subjectId = derivedVc?.credentialSubject?.id;
  if(!subjectId || !vp.holder || vp.holder !== subjectId) return {verified: false, reason: 'HOLDER_BINDING_MISMATCH'};
  return {verified: true, derivedVc};
}

// 3b. Xac minh dong thoi VP proof (lop ngoai, Holder) va VC proof (lop trong, Issuer)
export async function verifyBoundPresentation(params: {
  verifiablePresentation: any;
  expectedNonce: string;
  expectedAudience: string;
  documentLoader: any;
}): Promise<BoundVerifyResult> {
  const vp = params.verifiablePresentation;
  const identity = checkHolderIdentity(vp);
  if(!identity.verified) return identity;

  const suite = [
    new DataIntegrityProof({cryptosuite: rdfcCryptosuite}),
    new DataIntegrityProof({cryptosuite: createSdVerifySuite()})
  ];
  let result: any;
  try {
    result = await vc.verify({
      presentation: vp,
      challenge: params.expectedNonce,
      domain: params.expectedAudience,
      suite,
      documentLoader: params.documentLoader,
      checkStatus: async () => ({verified: true})
    });
  } catch(err: any) {
    return {verified: false, reason: 'CRYPTO_PROOF_OR_CHALLENGE_INVALID', detail: err?.message};
  }
  if(!result.verified) return {verified: false, reason: 'CRYPTO_PROOF_OR_CHALLENGE_INVALID', detail: result};
  return {verified: true, derivedVc: identity.derivedVc};
}

