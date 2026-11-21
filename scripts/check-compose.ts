import assert from 'node:assert/strict';
import {BitstringStatusList} from '../src/status/bitstring-status.js';
import {WalletClient} from '../src/services/wallet-client-sdk.js';

const issuer = process.env.ISSUER_PUBLIC_URL ?? 'http://localhost:4001';
const verifier = process.env.VERIFIER_PUBLIC_URL ?? 'http://localhost:4002';
const wallet = process.env.COMPOSE_WALLET_URL ?? 'http://localhost:3000';
const password = process.env.DEMO_PASSWORD;
assert.ok(password, 'Cần DEMO_PASSWORD của cụm thử nghiệm riêng');
const recordId = 'rec-deg-23020009';

async function json(base: string, path: string, status: number, body?: object, cookie?: string) {
  const r = await fetch(base + path, {
    method: body === undefined ? 'GET' : 'POST', signal: AbortSignal.timeout(15000),
    headers: {...(body === undefined ? {} : {'Content-Type': 'application/json'}), ...(cookie ? {Cookie: cookie} : {})},
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  assert.equal(r.status, status, path);
  return {data: await r.json(), cookie: r.headers.get('set-cookie')?.split(';')[0]};
}

async function studentToken() {
  return (await json(issuer, '/api/student-auth/login', 200, {
    method: 'sso', identifier: '23020009@vnu.edu.vn', password
  })).data.token as string;
}

async function claim(token: string, target: WalletClient, expected: number, id = recordId) {
  const headers = {Authorization: 'Bearer ' + token, 'Content-Type': 'application/json'};
  const challenge = await fetch(issuer + '/api/student/nonce', {method: 'POST', headers});
  assert.equal(challenge.status, 200);
  const {c_nonce, aud} = await challenge.json();
  const r = await fetch(issuer + '/api/student/claim', {
    method: 'POST', headers, body: JSON.stringify({
      recordId: id, holderDid: target.did, c_nonce, proof: await target.signOpenId4VciProof(c_nonce, aud)
    })
  });
  if(expected) assert.equal(r.status, expected);
  return {status: r.status, data: await r.json()};
}

const approver = await json(issuer, '/api/portal/auth/login', 200, {username: 'truongphong', password});
const registrar = await json(issuer, '/api/portal/auth/login', 200, {username: 'chuyenvien', password});
const hr = await json(verifier, '/api/rp/auth/login', 200, {username: 'hr.fpt', password});
const first = await json(wallet, '/api/wallet-portal/auth/login', 200, {
  method: 'sso', identifier: '23020009@vnu.edu.vn', password
});
const second = await json(wallet, '/api/wallet-portal/auth/login', 200, {
  method: 'sso', identifier: '23020114@vnu.edu.vn', password
});
assert.notEqual(first.data.walletDid, second.data.walletDid);

async function verify(credentialId: string, expected: number) {
  const request = (await json(verifier, '/api/verifier/request', 201, {claims: ['major']}, hr.cookie)).data.request;
  const draft = {request, credentialId};
  const preview = await json(wallet, '/api/wallet/preview', 200, draft, first.cookie);
  const result = await json(wallet, '/api/wallet/present', 200, {
    ...draft, consent: true, consentId: preview.data.consentId, submit: true
  }, first.cookie);
  assert.equal(result.data.submitted.status, expected);
  if(expected === 200) assert.equal(result.data.submitted.body.disclosed.gpa, undefined);
  return result.data.submitted.body;
}

async function verifyStatus(id: string, purpose: 'revocation' | 'suspension', expected: boolean) {
  const record = (await json(issuer, '/api/portal/records/' + id, 200, undefined, approver.cookie)).data.record;
  const path = '/status/degree-list-1' + (purpose === 'suspension' ? '-suspension' : '');
  const vc = (await json(issuer, path, 200)).data;
  assert.equal(vc.credentialSubject.statusPurpose, purpose);
  assert.equal(BitstringStatusList.decode(vc.credentialSubject.encodedList).get(record.statusListIndex), expected);
}

if(process.argv[2] === 'before-recreate') {
  const secondRecord = (await json(issuer, '/api/portal/records', 200, undefined, registrar.cookie))
    .data.items.find((item: any) => item.studentCode === '23020114' && item.kind === 'degree');
  assert.ok(secondRecord);
  if(secondRecord.status === 'PENDING_APPROVAL') await json(issuer, '/api/portal/records/' + secondRecord.id + '/approve', 200, {}, approver.cookie);
  const refs = await Promise.all(Array.from({length: 4}, () =>
    json(wallet, '/api/wallet-portal/claim', 200, {recordId}, first.cookie)));
  assert.equal(new Set(refs.map(r => r.data.statusListIndex)).size, 1);
  for(const entry of refs) assert.deepEqual(entry.data.credential, refs[0].data.credential);
  const courseId = (await json(issuer, '/api/portal/records', 200, undefined, approver.cookie))
    .data.items.find((item: any) => item.studentCode === '23020009' && item.kind === 'course' && item.status === 'APPROVED').id;
  const token = await studentToken();
  const [keyA, keyB] = await Promise.all([WalletClient.create(), WalletClient.create()]);
  const races = await Promise.all([claim(token, keyA, 0, courseId), claim(token, keyB, 0, courseId)]);
  assert.deepEqual(races.map(x => x.status).sort(), [200, 409]);
  const winner = races.find(r => r.status === 200)!;
  assert.notEqual(winner.data.statusListIndex, refs[0].data.statusListIndex);
  await verify(recordId, 200);
  await json(issuer, '/api/portal/records/' + recordId + '/suspend', 200, {reason: 'Kiểm tra vòng đời'}, approver.cookie);
  await verifyStatus(recordId, 'suspension', true);
  await verifyStatus(recordId, 'revocation', false);
  assert.equal((await verify(recordId, 400)).step, 'status');
  console.log('PASS: PostgreSQL issuance, concurrent claims, per-student wallets, form presentation, independent status bits');
} else if(process.argv[2] === 'after-recreate') {
  const me = (await json(wallet, '/api/wallet-portal/me', 200, undefined, first.cookie)).data;
  assert.ok(me.wallet.credentials.some((item: any) => item.id === recordId));
  await verifyStatus(recordId, 'suspension', true);
  assert.equal((await verify(recordId, 400)).step, 'status');
  await json(issuer, '/api/portal/records/' + recordId + '/reinstate', 200, {}, approver.cookie);
  await verify(recordId, 200);
  const proposal = (await json(wallet, '/api/wallet-portal/reissue', 200, {recordId, reason: 'Kiểm tra cấp lại'}, first.cookie)).data.record;
  const approval = await json(issuer, '/api/portal/records/batch-approve', 200, {recordIds: [proposal.id]}, approver.cookie);
  assert.deepEqual(approval.data.approvedIds, [proposal.id]);
  await verifyStatus(recordId, 'revocation', true);
  await json(issuer, '/api/portal/records/' + recordId + '/reinstate', 409, {}, approver.cookie);
  await json(wallet, '/api/wallet-portal/device/rotate', 200, {password}, first.cookie);
  const replacement = (await json(wallet, '/api/wallet-portal/claim', 200, {recordId: proposal.id}, first.cookie)).data;
  assert.notEqual(replacement.walletDid, first.data.walletDid);
  await verify(proposal.id, 200);
  console.log('PASS: issuer/wallet recreate, suspended credential, reinstatement, batch reissue, old revocation and new key');
} else {
  throw new Error('Chọn before-recreate hoặc after-recreate trên cụm thử sạch');
}
