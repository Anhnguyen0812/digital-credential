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
  test('P1 - issue va verify credential goc', async () => {
    const rs = await verifyBaseDegree(signed, setup, new StatusStore());
    expect(rs.verified).toBe(true);
    expect(signed.proof.cryptosuite).toBe('ecdsa-sd-2023');
  });

  test('P2 - chi chia se cac truong da chon', async () => {
    const s = disclosed.credentialSubject;
    expect(s.studentName).toBe('Nguyễn Phi Anh');
    expect(s.major).toBe('Công nghệ thông tin');
    expect(s.graduated).toBe(true);
    expect(s.gpa).toBeUndefined();
    expect(s.studentCode).toBeUndefined();
    expect(s.classification).toBeUndefined();

    const rs = await verifyDegree(disclosed, setup, new StatusStore());
    expect(rs.verified).toBe(true);
  });

  test('P3 - sua noi dung thi chu ky sai', async () => {
    const tampered = structuredClone(disclosed);
    tampered.credentialSubject.major = 'Khoa học máy tính';
    const rs = await verifyDegree(tampered, setup, new StatusStore());
    expect(rs.verified).toBe(false);
    expect(rs.cryptoVerified).toBe(false);
  });

  test('P4 - credential bi thu hoi se bi tu choi', async () => {
    const store = new StatusStore();
    expect((await verifyDegree(disclosed, setup, store)).verified).toBe(true);
    store.revoke(12);
    const rs = await verifyDegree(disclosed, setup, store);
    expect(rs.verified).toBe(false);
    expect(rs.cryptoVerified).toBe(true);
    expect(rs.statusVerified).toBe(false);
  });

  test('P5 - nonce chi duoc dung mot lan', async () => {
    const req = {nonce: 'n-test-100', audience: VERIFY_AUDIENCE};
    const vp = makePresentation(disclosed, req);
    const guard = new ReplayGuard();
    const store = new StatusStore();
    expect((await verifyPresentation(vp, req, guard, setup, store)).verified).toBe(true);
    const replay = await verifyPresentation(vp, req, guard, setup, store);
    expect(replay.verified).toBe(false);
    expect(replay.reason).toContain('da duoc dung');
  });

  test('P6 - audience sai se bi tu choi', async () => {
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
