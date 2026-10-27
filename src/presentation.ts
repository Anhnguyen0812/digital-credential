import type {PresentationRequest, SimplePresentation, VerifyResult} from './types.js';
import type {StatusStore} from './status-store.js';
import {verifyDegree} from './credential-service.js';

export class ReplayGuard {
  private used = new Set<string>();

  use(nonce: string) {
    if(this.used.has(nonce)) return false;
    this.used.add(nonce);
    return true;
  }
}

export function makePresentation(vc: any, req: PresentationRequest): SimplePresentation {
  return {
    type: ['VerifiablePresentation'],
    holder: vc.credentialSubject.id,
    nonce: req.nonce,
    audience: req.audience,
    createdAt: new Date().toISOString(),
    verifiableCredential: [vc]
  };
}

export async function verifyPresentation(
  vp: SimplePresentation,
  expected: PresentationRequest,
  guard: ReplayGuard,
  setup: any,
  store: StatusStore
): Promise<VerifyResult> {
  if(vp.audience !== expected.audience) {
    return {verified: false, reason: 'audience khong dung'};
  }
  if(vp.nonce !== expected.nonce) {
    return {verified: false, reason: 'nonce khong dung'};
  }
  if(!guard.use(vp.nonce)) {
    return {verified: false, reason: 'nonce da duoc dung'};
  }
  if(!Array.isArray(vp.verifiableCredential) || vp.verifiableCredential.length !== 1) {
    return {verified: false, reason: 'presentation khong hop le'};
  }
  return verifyDegree(vp.verifiableCredential[0], setup, store);
}
