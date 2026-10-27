import {afterAll, beforeAll, describe, expect, test} from 'vitest';
import {gzipSync} from 'node:zlib';
import {BitstringStatusList, MIN_LIST_LENGTH} from '../src/bitstring-status.js';
import {RedisReplayGuard} from '../src/redis-replay-guard.js';
import {createApp} from '../src/server.js';

const PORT = 3907;
let app: Awaited<ReturnType<typeof createApp>>;

async function post(path: string, body: any) {
  const r = await fetch(`http://localhost:${PORT}${path}`, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  });
  return {status: r.status, body: await r.json()};
}

// Chay du 1 vong: verifier tao request -> wallet present -> tra ve {request, presentation}
async function walletFlow(credential: any, claims = ['major']) {
  const {body: rq} = await post('/api/verifier/request', {claims});
  const {body: pr} = await post('/api/wallet/present', {request: rq.request, credential, consent: true});
  return {request: rq.request, presentation: pr};
}

describe('W1 - W3C Bitstring Status List v1.0', () => {
  test('W1.1 - do dai mac dinh 131.072 bit, tu choi danh sach ngan hon', () => {
    expect(new BitstringStatusList().length).toBe(MIN_LIST_LENGTH);
    expect(() => new BitstringStatusList(1024)).toThrow();
  });

  test('W1.2 - index 0 la bit trai nhat; encode -> decode giu nguyen bit', () => {
    const l = new BitstringStatusList();
    l.set(0, true); l.set(8321, true); l.set(131_071, true);
    const enc = l.encode();
    expect(enc.startsWith('u')).toBe(true);
    const raw = Buffer.from(enc.slice(1), 'base64url');
    expect(raw[0]).toBe(0x1f); expect(raw[1]).toBe(0x8b); // magic number GZIP (RFC 1952)
    const d = BitstringStatusList.decode(enc);
    expect(d.get(0)).toBe(true); expect(d.get(8321)).toBe(true); expect(d.get(131_071)).toBe(true);
    expect(d.get(1)).toBe(false); expect(d.get(8320)).toBe(false);
  });

  test('W1.3 - chong zip bomb: tu choi du lieu giai nen > 2 MB', () => {
    const bomb = 'u' + gzipSync(Buffer.alloc(3 * 1024 * 1024)).toString('base64url');
    expect(() => BitstringStatusList.decode(bomb)).toThrow();
  });
});

describe('W2 - Redis ReplayGuard (Redis server that)', () => {
  let g: RedisReplayGuard;
  beforeAll(async () => { g = new RedisReplayGuard('127.0.0.1', 6379, 300); await g.connect(); });
  afterAll(() => g.close());

  test('W2.1 - lan dau OK, lan hai bi tu choi, TTL dat 300 giay', async () => {
    const n = 'nonce-' + Date.now();
    expect(await g.consume(n, 'aud-A')).toBe(true);
    expect(await g.consume(n, 'aud-A')).toBe(false);
    const ttl = await g.ttl(n, 'aud-A');
    expect(ttl).toBeGreaterThan(290); expect(ttl).toBeLessThanOrEqual(300);
  });

  test('W2.2 - cung nonce nhung khac audience la khoa khac nhau', async () => {
    const n = 'nonce-aud-' + Date.now();
    expect(await g.consume(n, 'aud-A')).toBe(true);
    expect(await g.consume(n, 'aud-B')).toBe(true);
  });
});

describe('W3 - Luong HTTP end-to-end Issuer -> Wallet -> Verifier', () => {
  let credential: any;
  let statusListIndex: number;

  beforeAll(async () => {
    app = await createApp({port: PORT});
    const {body} = await post('/api/issuer/issue', {});
    credential = body.credential;
    statusListIndex = body.statusListIndex;
  });
  afterAll(async () => { await app.close(); });

  test('W3.1 - Status List Credential co chu ky va encodedList GZIP', async () => {
    const r = await fetch(`http://localhost:${PORT}/status/degree-list-1`);
    const slc = await r.json();
    expect(slc.type).toContain('BitstringStatusListCredential');
    expect(slc.proof?.cryptosuite).toBe('ecdsa-sd-2023');
    expect(slc.credentialSubject.encodedList.startsWith('u')).toBe(true);
  });

  test('W3.2 - wallet preview phan loai dung 3 nhom', async () => {
    const {body: rq} = await post('/api/verifier/request', {claims: ['major']});
    const {body} = await post('/api/wallet/preview', {request: rq.request, credential});
    expect(body.mandatory).toEqual(expect.arrayContaining(['studentName', 'graduated']));
    expect(body.requestedOptional).toEqual(['major']);
    expect(body.hidden).toEqual(expect.arrayContaining(['gpa', 'studentCode', 'classification']));
  });

  test('W3.3 - khong co consent thi wallet khong tao presentation', async () => {
    const {body: rq} = await post('/api/verifier/request', {claims: ['major']});
    const r = await post('/api/wallet/present', {request: rq.request, credential, consent: false});
    expect(r.status).toBe(400);
  });

  test('W3.4 - luong hop le: xac minh 3 buoc thanh cong, GPA bi an', async () => {
    const {presentation} = await walletFlow(credential);
    const r = await post('/api/verifier/direct-post', presentation);
    expect(r.status).toBe(200);
    expect(r.body.verified).toBe(true);
    expect(r.body.disclosed.major).toBe('Công nghệ thông tin');
    expect(r.body.disclosed.gpa).toBeUndefined();
    expect(r.body.disclosed.studentCode).toBeUndefined();
  });

  test('W3.5 - gui lai cung presentation thi bi chan 409', async () => {
    const {presentation} = await walletFlow(credential);
    expect((await post('/api/verifier/direct-post', presentation)).status).toBe(200);
    const replay = await post('/api/verifier/direct-post', presentation);
    expect(replay.status).toBe(409);
    expect(replay.body.step).toBe('replay');
  });

  test('W3.6 - 200 request dong thoi cung nonce: dung 1 request duoc chap nhan', async () => {
    const {presentation} = await walletFlow(credential);
    const results = await Promise.all(Array.from({length: 200}, () => post('/api/verifier/direct-post', presentation)));
    const ok = results.filter(r => r.status === 200).length;
    const conflict = results.filter(r => r.status === 409).length;
    expect(ok).toBe(1);
    expect(conflict).toBe(199);
  });

  test('W3.7 - sua noi dung presentation thi buoc chu ky that bai', async () => {
    const {presentation} = await walletFlow(credential);
    presentation.vp_token.degree[0].verifiableCredential[0].credentialSubject.major = 'Khoa học máy tính';
    const r = await post('/api/verifier/direct-post', presentation);
    expect(r.body.verified).toBe(false);
    expect(r.body.step).toBe('crypto');
  });

  test('W3.8 - truong thu hoi -> verifier lay lai status list va tu choi', async () => {
    await post('/api/issuer/revoke', {statusListIndex});
    const {presentation} = await walletFlow(credential);
    const r = await post('/api/verifier/direct-post', presentation);
    expect(r.body.verified).toBe(false);
    expect(r.body.step).toBe('status');
  });
});
