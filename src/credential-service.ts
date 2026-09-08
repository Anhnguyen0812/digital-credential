import {randomUUID} from 'node:crypto';
import * as vc from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  createConfirmCryptosuite,
  createDiscloseCryptosuite,
  createSignCryptosuite,
  createVerifyCryptosuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {DEGREE_CONTEXT, ISSUER_ID, STATUS_URL} from './config.js';
import type {DegreeInput, VerifyResult} from './types.js';
import {StatusStore} from './status-store.js';

export function makeUnsignedDegree(data: DegreeInput) {
  const idx = data.statusIndex ?? 12;
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', DEGREE_CONTEXT],
    id: data.id,
    type: ['VerifiableCredential', 'DegreeCredential'],
    issuer: ISSUER_ID,
    validFrom: '2026-08-01T00:00:00Z',
    validUntil: '2036-08-01T00:00:00Z',
    credentialSubject: data.subject,
    credentialStatus: {
      id: STATUS_URL + '#' + idx,
      type: 'SimpleStatusEntry',
      myStatusIndex: String(idx),
      myStatusPurpose: 'revocation',
      myStatusUrl: STATUS_URL
    }
  };
}

export async function issueDegree(input: DegreeInput, setup: any) {
  const credential = makeUnsignedDegree(input);
  const suite = new DataIntegrityProof({
    signer: setup.keyPair.signer(),
    cryptosuite: createSignCryptosuite({
      mandatoryPointers: [
        '/issuer',
        '/validFrom',
        '/validUntil',
        '/credentialStatus'
      ]
    })
  });

  suite.proof = {id: 'urn:uuid:' + randomUUID()};
  return vc.issue({credential, suite, documentLoader: setup.documentLoader});
}

export async function discloseDegree(baseVc: any, setup: any, proofId?: string) {
  const id = proofId || baseVc?.proof?.id;
  if(!id) throw new Error('Proof ID not found');

  const suite = new DataIntegrityProof({
    cryptosuite: createDiscloseCryptosuite({
      proofId: id,
      selectivePointers: [
        '/credentialSubject/id',
        '/credentialSubject/studentName',
        '/credentialSubject/major',
        '/credentialSubject/graduated'
      ]
    })
  });

  return vc.derive({
    verifiableCredential: baseVc,
    suite,
    documentLoader: setup.documentLoader
  });
}

async function checkProof(credential: any, setup: any, isBase = false) {
  try {
    const cryptosuite = isBase ? createConfirmCryptosuite() : createVerifyCryptosuite();
    const suite = new DataIntegrityProof({cryptosuite});
    const result = await vc.verifyCredential({
      credential,
      suite,
      documentLoader: setup.documentLoader,
      checkStatus: async () => ({verified: true})
    });
    return {verified: result.verified === true, result};
  } catch(err: any) {
    return {verified: false, error: err?.message || String(err)};
  }
}

export async function verifyCrypto(credential: any, setup: any) {
  return checkProof(credential, setup, false);
}

export async function verifyBaseCrypto(credential: any, setup: any) {
  return checkProof(credential, setup, true);
}

function withStatus(cryptoResult: any, credential: any, store: StatusStore): VerifyResult {
  if(!cryptoResult.verified) {
    return {
      verified: false,
      cryptoVerified: false,
      statusVerified: false,
      reason: 'Invalid signature or credential content'
    };
  }

  const status = store.check(credential);
  if(!status.verified) {
    return {
      verified: false,
      cryptoVerified: true,
      statusVerified: false,
      reason: status.reason
    };
  }
  return {verified: true, cryptoVerified: true, statusVerified: true};
}

export async function verifyBaseDegree(credential: any, setup: any, store: StatusStore) {
  const cryptoResult = await verifyBaseCrypto(credential, setup);
  return withStatus(cryptoResult, credential, store);
}

export async function verifyDegree(
  credential: any,
  setup: any,
  store: StatusStore
): Promise<VerifyResult> {
  const cryptoResult = await verifyCrypto(credential, setup);
  return withStatus(cryptoResult, credential, store);
}
