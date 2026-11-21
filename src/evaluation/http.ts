import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {bytes, command, count, startRun, timed} from './run.js';

const project = process.env.BENCH_COMPOSE_PROJECT ?? 'khoaluan-benchmark';
const issuer = process.env.ISSUER_PUBLIC_URL ?? 'http://localhost:4001';
const verifier = process.env.VERIFIER_PUBLIC_URL ?? 'http://localhost:4002';
const wallet = process.env.COMPOSE_WALLET_URL ?? 'http://localhost:3000';
const password = process.env.DEMO_PASSWORD;
const recordId = 'rec-deg-23020009';
const claims = ['major'];

class HttpFailure extends Error {
  constructor(readonly endpoint: string, readonly status: number, readonly step?: string) {
    super(`${endpoint}: HTTP ${status}${step ? ' at ' + step : ''}`);
  }
}

async function post(base: string, endpoint: string, expected: number, body: object, cookie?: string) {
  const result = await fetch(base + endpoint, {method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
    headers: {'Content-Type': 'application/json', ...(cookie ? {Cookie: cookie} : {})}, body: JSON.stringify(body)});
  const data = await result.json();
  if(result.status !== expected) throw new HttpFailure(endpoint, result.status, data.step);
  return {data, cookie: result.headers.get('set-cookie')?.split(';')[0]};
}

function serviceMetadata() {
  const get = (...args: string[]) => command('docker', ['compose', '-p', project, ...args]);
  const images = get('ps', '-q').split(/\r?\n/).filter(Boolean).map(id =>
    command('docker', ['inspect', '--format', '{{index .Config.Labels "com.docker.compose.service"}} {{.Config.Image}} {{.Image}}', id]));
  return {docker: command('docker', ['version', '--format', '{{.Server.Version}}']),
    compose: get('version', '--short'), images,
    postgres: get('exec', '-T', 'postgres-db', 'postgres', '--version'),
    redis: get('exec', '-T', 'redis-guard', 'redis-server', '--version'),
    serviceNode: get('exec', '-T', 'wallet-pwa', 'node', '--version')};
}

async function main() {
  assert.ok(password, 'Set DEMO_PASSWORD for the disposable Compose stack');
  const concurrency = (process.env.BENCH_CONCURRENCY ?? '1,5,20,50').split(',').map(Number);
  if(concurrency.some(value => !Number.isSafeInteger(value) || value < 1)) throw new Error('Invalid BENCH_CONCURRENCY');
  const batches = count('BENCH_BATCHES', 10);
  const warmup = count('BENCH_WARMUP', 10, 0);
  const health = await (await fetch(verifier + '/health', {signal: AbortSignal.timeout(5000)})).json();
  const run = startRun('http', {issuer, verifier, wallet, project, concurrency, batches, warmup, claims,
    cacheMode: health.status, dataset: 'one seeded degree and authenticated holder/verifier', services: serviceMetadata()});
  const [holderSession, holderLoginMs] = await timed(() => post(wallet, '/api/wallet-portal/auth/login', 200, {
    method: 'sso', identifier: '23020009@vnu.edu.vn', password
  }));
  const [hr, verifierLoginMs] = await timed(() => post(verifier, '/api/rp/auth/login', 200, {username: 'hr.fpt', password}));
  assert.ok(holderSession.cookie && hr.cookie);
  const [claim, claimMs] = await timed(() => post(wallet, '/api/wallet-portal/claim', 200, {recordId}, holderSession.cookie));
  assert.ok(claim.data.credential);
  run.sample({phase: 'setup', ok: true, holderLoginMs, verifierLoginMs, claimMs, baseBytes: bytes(claim.data.credential)});

  async function verify(phase: string, parallel: number, batch: number, lane: number) {
    const start = performance.now();
    const sample = {ok: false, parallel, batch, lane};
    try {
      const [request, requestMs] = await timed(() => post(verifier, '/api/verifier/request', 201, {claims}, hr.cookie));
      const draft = {request: request.data.request, credentialId: recordId};
      const [preview, previewMs] = await timed(() => post(wallet, '/api/wallet/preview', 200, draft, holderSession.cookie));
      const [response, presentMs] = await timed(() => post(wallet, '/api/wallet/present', 200, {
        ...draft, approvedClaims: claims, consentId: preview.data.consentId, consent: true, submit: true
      }, holderSession.cookie));
      const {data} = response;
      const e2eMs = performance.now() - start;
      assert.ok(data.submitted);
      const {status, body} = data.submitted;
      if(status !== 200) throw new HttpFailure('direct_post', status, body.step);
      assert.equal(body.verified, true);
      const disclosed = Object.keys(body.disclosed).sort();
      assert.deepEqual(disclosed, ['graduated', 'id', 'major', 'studentName']);
      const form = new URLSearchParams({state: data.state, vp_token: JSON.stringify(data.vp_token)});
      return {phase, ...sample, ok: true, requestMs, previewMs, presentMs, e2eMs, disclosed,
        walletDeriveMs: data.deriveMs, walletSignMs: data.signMs, verifierCryptoMs: body.timings.cryptoMs,
        verifierStatusMs: body.timings.statusMs, verifierRedisMs: body.timings.redisMs,
        postBodyBytes: Buffer.byteLength(form.toString(), 'utf8')};
    } catch(error) {
      return {phase, ...sample, failureMs: performance.now() - start,
        status: error instanceof HttpFailure ? error.status : undefined,
        error: error instanceof TypeError ? (error.cause as Error | undefined)?.message ?? error.message :
          error instanceof Error ? error.message : String(error)};
    }
  }

  const cold = await verify('first', 1, 0, 0);
  run.sample(cold);
  assert.ok(cold.ok, 'First session failed; see samples.jsonl');
  let failures = 0;
  for(let round = 0; round < warmup; round++) {
    const row = await verify('warmup', 1, round, 0);
    run.sample(row);
    failures += Number(!row.ok);
  }
  for(const parallel of concurrency) {
    for(let batch = 0; batch < batches; batch++) {
      const rows = await Promise.all(Array.from({length: parallel}, (_, lane) => verify('measured', parallel, batch, lane)));
      for(const row of rows) {
        run.sample(row);
        failures += Number(!row.ok);
      }
    }
    const containers = command('docker', ['compose', '-p', project, 'ps', '-q']).split(/\r?\n/).filter(Boolean);
    const stats = command('docker', ['stats', '--no-stream', '--format', '{{json .}}', ...containers]);
    run.sample({phase: 'post-batch-resources', parallel, stats: stats.split(/\r?\n/).map(line => JSON.parse(line))});
  }
  run.finish();
  assert.equal(failures, 0, 'HTTP failures retained in samples.jsonl; see summary');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
