import {beforeAll, describe, expect, test} from 'vitest';
import {makeIssuerSetup} from '../src/issuer-setup.js';
import {
  discloseDegree,
  issueDegree,
  verifyBaseDegree,
  verifyDegree
} from '../src/credential-service.js';
import {StatusStore} from '../src/status-store.js';
import {makePresentation, ReplayGuard, verifyPresentation} from '../src/presentation.js';
import {sampleInput} from '../src/sample.js';
import {VERIFY_AUDIENCE} from '../src/config.js';

let setup: any;
let signed: any;
let disclosed: any;

beforeAll(async () => {
  setup = await makeIssuerSetup();
  signed = await issueDegree(sampleInput, setup);
  disclosed = await discloseDegree(signed, setup);
});

describe('DegreeCredential ECDSA-SD', () => {
  test('P1 - issue and verify the original credential', async () => {
    const rs = await verifyBaseDegree(signed, setup, new StatusStore());
    expect(rs.verified).toBe(true);
    expect(signed.proof.cryptosuite).toBe('ecdsa-sd-2023');
  });

  test('P2 - disclose only the selected subject fields', async () => {
    const s = disclosed.credentialSubject;
    expect(s.studentName).toBe('Nguyen Phi Anh');
    expect(s.major).toBe('Information Technology');
    expect(s.graduated).toBe(true);
    expect(s.gpa).toBeUndefined();
    expect(s.studentCode).toBeUndefined();
    expect(s.classification).toBeUndefined();

    const rs = await verifyDegree(disclosed, setup, new StatusStore());
    expect(rs.verified).toBe(true);
  });

  test('P3 - reject a credential with tampered content', async () => {
    const tampered = structuredClone(disclosed);
    tampered.credentialSubject.major = 'Computer Science';
    const rs = await verifyDegree(tampered, setup, new StatusStore());
    expect(rs.verified).toBe(false);
    expect(rs.cryptoVerified).toBe(false);
  });

  test('P4 - reject a revoked credential', async () => {
    const store = new StatusStore();
    expect((await verifyDegree(disclosed, setup, store)).verified).toBe(true);
    store.revoke(12);
    const rs = await verifyDegree(disclosed, setup, store);
    expect(rs.verified).toBe(false);
    expect(rs.cryptoVerified).toBe(true);
    expect(rs.statusVerified).toBe(false);
  });

  test('P5 - allow each nonce to be used only once', async () => {
    const req = {nonce: 'n-test-100', audience: VERIFY_AUDIENCE};
    const vp = makePresentation(disclosed, req);
    const guard = new ReplayGuard();
    const store = new StatusStore();
    expect((await verifyPresentation(vp, req, guard, setup, store)).verified).toBe(true);
    const replay = await verifyPresentation(vp, req, guard, setup, store);
    expect(replay.verified).toBe(false);
    expect(replay.reason).toContain('already been used');
  });

  test('P6 - reject a mismatched audience', async () => {
    const req = {nonce: 'n-test-200', audience: VERIFY_AUDIENCE};
    const vp = makePresentation(disclosed, req);
    const wrongReq = {...req, audience: 'https://other.example/verify'};
    const rs = await verifyPresentation(
      vp,
      wrongReq,
      new ReplayGuard(),
      setup,
      new StatusStore()
    );
    expect(rs.verified).toBe(false);
    expect(rs.reason).toContain('audience');
  });
});
