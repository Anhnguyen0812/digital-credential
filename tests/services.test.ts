import {afterAll, beforeAll, describe, expect, test} from 'vitest';
import {createIssuerApp} from '../src/services/issuer-app.js';
import {createVerifierApp} from '../src/services/verifier-app.js';
import {createWalletApp} from '../src/services/wallet-app.js';
import {WalletClient} from '../src/services/wallet-client-sdk.js';

const ISSUER = 'http://localhost:4911';
const VERIFIER = 'http://localhost:4912';
let issuer: Awaited<ReturnType<typeof createIssuerApp>>;
let verifier: Awaited<ReturnType<typeof createVerifierApp>>;
let walletApp: Awaited<ReturnType<typeof createWalletApp>>;
let wallet: WalletClient;

const post = async (url: string, body: any) => {
  const r = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
  return {status: r.status, body: await r.json()};
};
const issueDegree = async () => {
  const r = await post(`${ISSUER}/api/issuer/issue-degree`, {holderDid: wallet.did});
  wallet.addCredential(r.body.recordId, r.body.credential);
  return r.body;
};
async function newRequest(claims: string[] = ['major'], credentialType = 'DegreeCredential') {
  return (await post(`${VERIFIER}/api/verifier/request`, {claims, credentialType})).body.request;
}
async function presentAndPost(credentialId: string, claims = ['major'], simulate: any = 'normal', credentialType = 'DegreeCredential') {
  const request = await newRequest(claims, credentialType);
  const out = await wallet.present({request, credentialId, consent: true, simulate});
  const r = await post(`${VERIFIER}/api/verifier/direct-post`, {state: out.state, vp_token: out.vp_token});
  return {request, out, r};
}

beforeAll(async () => {
  wallet = await WalletClient.create();
  issuer = await createIssuerApp({port: 4911, publicUrl: ISSUER});
  verifier = await createVerifierApp({port: 4912, publicUrl: VERIFIER, issuerPublicUrl: ISSUER, issuerInternalUrl: ISSUER});
  walletApp = await createWalletApp({port: 3913, issuerPublicUrl: ISSUER, verifierPublicUrl: VERIFIER, wallet});
});
afterAll(async () => {
  await walletApp?.close(); await verifier?.close(); await issuer?.close();
});

describe('W5 - Kien truc 3 mien tach roi (Issuer 4001 / Verifier 4002 / Wallet 3000)', () => {
  test('W5.1 - Issuer xuat ban did.json co issuer-key-1 va approver-key-1', async () => {
    const did = await (await fetch(`${ISSUER}/.well-known/did.json`)).json();
    expect(did.id).toBe(issuer.issuerDid);
    expect(did.verificationMethod.map((v: any) => v.id)).toEqual(expect.arrayContaining([`${issuer.issuerDid}#issuer-key-1`, `${issuer.issuerDid}#approver-key-1`]));
  });

  test('W5.2 - Luong hop le (4 buoc): GPA/MSSV bi an, Verifier khong nhan Base VC', async () => {
    const {recordId} = await issueDegree();
    const {r, out} = await presentAndPost(recordId);
    expect(r.status).toBe(200);
    expect(r.body.verified).toBe(true);
    expect(r.body.disclosed.major).toBe('Công nghệ thông tin');
    expect(r.body.disclosed.gpa).toBeUndefined();
    expect(r.body.disclosed.studentCode).toBeUndefined();
    expect(JSON.stringify(out.vp_token)).not.toContain('3.65');
  });

  test('W5.3 - Bang cap lai 2 buoc (ingest -> approve) + so goc + ban scan watermark dong', async () => {
    const ing = await post(`${ISSUER}/api/issuer/legacy/ingest`, {holderDid: wallet.did});
    expect(ing.body.status).toBe('PENDING_REVIEW');
    const apr = await post(`${ISSUER}/api/issuer/legacy/approve`, {recordId: ing.body.recordId});
    expect(apr.status).toBe(201);
    wallet.addCredential(apr.body.recordId, apr.body.credential);

    const {request, r} = await presentAndPost(apr.body.recordId);
    expect(r.status).toBe(200);
    expect(r.body.disclosed.legacyProvenance.sourceDocumentDigest).toBe(ing.body.sourceDocumentDigest);
    expect(r.body.legacyDocument).toBeTruthy();

    const scan = await fetch(r.body.legacyDocument);
    expect(scan.status).toBe(200);
    expect(await scan.text()).toContain('Công ty Tuyển dụng Demo');
    // khong co receipt -> issuer tu choi
    const direct = await fetch(`${ISSUER}/api/legacy/document/${encodeURIComponent(ing.body.sourceDocumentDigest)}`);
    expect(direct.status).toBe(401);
    expect(request.state).toBeTruthy();
  });

  test('W5.4 - 200 luong replay dong thoi: dung 1 thanh cong, 199 bi 409', async () => {
    const {recordId} = await issueDegree();
    const request = await newRequest();
    const out = await wallet.present({request, credentialId: recordId, consent: true});
    const results = await Promise.all(Array.from({length: 200}, () => post(`${VERIFIER}/api/verifier/direct-post`, {state: out.state, vp_token: out.vp_token})));
    expect(results.filter(x => x.status === 200).length).toBe(1);
    expect(results.filter(x => x.status === 409).length).toBe(199);
  });

  test('W5.5 - Sua "Cong nghe thong tin" -> "Khoa hoc may tinh" bi chan 400 o tang ecdsa-sd-2023', async () => {
    const {recordId} = await issueDegree();
    const request = await newRequest();
    const out = await wallet.present({request, credentialId: recordId, consent: true});
    out.vp_token.cred[0].verifiableCredential[0].credentialSubject.major = 'Khoa học máy tính';
    const r = await post(`${VERIFIER}/api/verifier/direct-post`, {state: out.state, vp_token: out.vp_token});
    expect(r.status).toBe(400);
    expect(r.body.attackType).toBe('TAMPER');
  });

  test('W5.6 - Holder spoof (khoa Attacker) va Cross-Verifier (sai audience) bi chan 401', async () => {
    const {recordId} = await issueDegree();
    const a = await presentAndPost(recordId, ['major'], 'attacker-key');
    expect(a.r.status).toBe(401);
    const b = await presentAndPost(recordId, ['major'], 'wrong-audience');
    expect(b.r.status).toBe(401);
    expect(b.r.body.attackType).toBe('HOLDER_SPOOF');
  });

  test('W5.7 - Thu hoi: ETAG_REVALIDATE chan ngay; TTL_ONLY tra ve du lieu cu trong TTL (danh doi rieng tu/do tuoi)', async () => {
    const d1 = await issueDegree();
    expect((await presentAndPost(d1.recordId)).r.status).toBe(200); // nap cache (ETag)
    await post(`${VERIFIER}/api/verifier/config`, {mode: 'ETAG_REVALIDATE'});
    await post(`${ISSUER}/api/issuer/revoke`, {statusListIndex: d1.statusListIndex});
    const blocked = await presentAndPost(d1.recordId);
    expect(blocked.r.status).toBe(400);
    expect(blocked.r.body.attackType).toBe('REVOKED');

    // TTL_ONLY: cache con han -> verifier chua biet
    await post(`${VERIFIER}/api/verifier/config`, {mode: 'TTL_ONLY', ttlSeconds: 300, invalidate: true});
    const d2 = await issueDegree();
    expect((await presentAndPost(d2.recordId)).r.status).toBe(200); // cache moi nhat (chua thu hoi)
    await post(`${ISSUER}/api/issuer/revoke`, {statusListIndex: d2.statusListIndex});
    const stale = await presentAndPost(d2.recordId);
    expect(stale.r.status).toBe(200);
    const m = (await (await fetch(`${VERIFIER}/api/verifier/metrics`)).json()).status;
    expect(m.cacheHits).toBeGreaterThan(0);
    await post(`${VERIFIER}/api/verifier/config`, {invalidate: true});
    expect((await presentAndPost(d2.recordId)).r.status).toBe(400);
    await post(`${VERIFIER}/api/verifier/config`, {mode: 'ETAG_REVALIDATE'});
  });

  test('W5.8 - CourseCertificate qua dich vu: hop le va qua han bi tu choi', async () => {
    const ok = await post(`${ISSUER}/api/issuer/issue-course`, {holderDid: wallet.did, validUntil: '2036-01-15T00:00:00Z'});
    wallet.addCredential(ok.body.recordId, ok.body.credential);
    const good = await presentAndPost(ok.body.recordId, ['skills', 'courseHours'], 'normal', 'CourseCertificateCredential');
    expect(good.r.status).toBe(200);
    expect(good.r.body.disclosed.grade).toBeUndefined();
    expect(good.r.body.disclosed.skills).toContain('Applied Cryptography');

    const old = await post(`${ISSUER}/api/issuer/issue-course`, {holderDid: wallet.did, validFrom: '2020-01-01T00:00:00Z', validUntil: '2021-01-01T00:00:00Z'});
    wallet.addCredential(old.body.recordId, old.body.credential);
    const bad = await presentAndPost(old.body.recordId, ['skills'], 'normal', 'CourseCertificateCredential');
    expect(bad.r.status).toBe(400);
    expect(bad.r.body.attackType).toBe('EXPIRED');
  });

  test('W5.9 - Wallet-agent HTTP: receive + preview 3 nhom + present(submit) qua Verifier', async () => {
    const info = await (await fetch('http://localhost:3913/api/wallet/info')).json();
    const iss = await post(`${ISSUER}/api/issuer/issue-degree`, {holderDid: info.did});
    expect((await post('http://localhost:3913/api/wallet/receive', {id: iss.body.recordId, credential: iss.body.credential})).status).toBe(201);
    const request = await newRequest(['major']);
    const pv = await post('http://localhost:3913/api/wallet/preview', {request, credentialId: iss.body.recordId});
    expect(pv.body.mandatory).toEqual(expect.arrayContaining(['studentName', 'graduated']));
    expect(pv.body.requestedOptional).toEqual(['major']);
    expect(pv.body.hidden).toEqual(expect.arrayContaining(['gpa', 'studentCode']));
    const noConsent = await post('http://localhost:3913/api/wallet/present', {request, credentialId: iss.body.recordId, consent: false});
    expect(noConsent.status).toBe(400);
    const pr = await post('http://localhost:3913/api/wallet/present', {request, credentialId: iss.body.recordId, consent: true, submit: true});
    expect(pr.body.submitted.status).toBe(200);
  });
});
