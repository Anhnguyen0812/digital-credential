import * as fs from 'node:fs';
import * as path from 'node:path';
import {performance} from 'node:perf_hooks';
import {BitstringStatusList, MIN_LIST_LENGTH} from './bitstring-status.js';
import {createApp} from './server.js';

function stats(values: number[]) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  const p95Idx = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95));
  return {
    min: Number(sorted[0].toFixed(2)),
    median: Number(median.toFixed(2)),
    p95: Number(sorted[p95Idx].toFixed(2)),
    max: Number(sorted[sorted.length - 1].toFixed(2))
  };
}

async function post(baseUrl: string, endpoint: string, body: any) {
  const r = await fetch(`${baseUrl}${endpoint}`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return {status: r.status, body: await r.json()};
}

async function runBenchmark() {
  console.log('=== KHOA LUAN WEEK 07 REAL BENCHMARK ===');
  const port = 3908;
  const app = await createApp({port});
  const baseUrl = app.baseUrl;

  const warmup = 5;
  const rounds = 30;

  const tBitstringEncode: number[] = [];
  const tBitstringDecode: number[] = [];
  const tIssueApi: number[] = [];
  const tRequestApi: number[] = [];
  const tPreviewApi: number[] = [];
  const tPresentApi: number[] = [];
  const tVerifyTotalApi: number[] = [];
  const tRedisStep: number[] = [];
  const tCryptoStep: number[] = [];
  const tStatusStep: number[] = [];

  let encodedBitstringSample = '';
  let statusListCredSample: any = null;
  let lastPresentationSample: any = null;

  // Issue 1 credential de test luong chia se
  const issuedRes = await post(baseUrl, '/api/issuer/issue', {});
  const baseVc = issuedRes.body.credential;

  // Lay Status List Credential mau
  const slcRes = await fetch(`${baseUrl}/status/degree-list-1`);
  statusListCredSample = await slcRes.json();

  for (let i = 0; i < warmup + rounds; i++) {
    const isWarmup = i < warmup;

    // 1. Bitstring encode & decode
    const list = new BitstringStatusList(MIN_LIST_LENGTH);
    list.set(12, true);
    list.set(8321, true);

    const e0 = performance.now();
    const enc = list.encode();
    const e1 = performance.now();
    if (!isWarmup) tBitstringEncode.push(e1 - e0);
    encodedBitstringSample = enc;

    const d0 = performance.now();
    const dec = BitstringStatusList.decode(enc);
    const d1 = performance.now();
    if (!isWarmup) tBitstringDecode.push(d1 - d0);
    if (!dec.get(8321)) throw new Error('Bitstring decode error');

    // 2. Issue API
    const i0 = performance.now();
    await post(baseUrl, '/api/issuer/issue', {});
    const i1 = performance.now();
    if (!isWarmup) tIssueApi.push(i1 - i0);

    // 3. Verifier Request API (OpenID4VP + DCQL)
    const r0 = performance.now();
    const reqRes = await post(baseUrl, '/api/verifier/request', {claims: ['major', 'graduationDate']});
    const r1 = performance.now();
    if (!isWarmup) tRequestApi.push(r1 - r0);

    // 4. Wallet Preview API
    const p0 = performance.now();
    await post(baseUrl, '/api/wallet/preview', {request: reqRes.body.request, credential: baseVc});
    const p1 = performance.now();
    if (!isWarmup) tPreviewApi.push(p1 - p0);

    // 5. Wallet Present API (Selective Disclosure)
    const pr0 = performance.now();
    const presRes = await post(baseUrl, '/api/wallet/present', {
      request: reqRes.body.request,
      credential: baseVc,
      consent: true
    });
    const pr1 = performance.now();
    if (!isWarmup) tPresentApi.push(pr1 - pr0);
    lastPresentationSample = presRes.body;

    // 6. Verifier Direct-Post API (3-step verification)
    const v0 = performance.now();
    const verRes = await post(baseUrl, '/api/verifier/direct-post', presRes.body);
    const v1 = performance.now();
    if (!verRes.body.verified) throw new Error('Verification failed in benchmark');
    if (!isWarmup) {
      tVerifyTotalApi.push(v1 - v0);
      tRedisStep.push(verRes.body.timings.redisMs);
      tCryptoStep.push(verRes.body.timings.cryptoMs);
      tStatusStep.push(verRes.body.timings.statusMs);
    }
  }

  // 7. Kiem thu 200 concurrent replay requests
  const replayReq = await post(baseUrl, '/api/verifier/request', {claims: ['major']});
  const replayPres = await post(baseUrl, '/api/wallet/present', {
    request: replayReq.body.request,
    credential: baseVc,
    consent: true
  });
  const c0 = performance.now();
  const concurrentResults = await Promise.all(
    Array.from({length: 200}, () => post(baseUrl, '/api/verifier/direct-post', replayPres.body))
  );
  const c1 = performance.now();
  const accepted200 = concurrentResults.filter(r => r.status === 200).length;
  const rejected409 = concurrentResults.filter(r => r.status === 409).length;

  const rawBitstringBytes = MIN_LIST_LENGTH / 8; // 16,384 bytes
  const encodedBitstringChars = encodedBitstringSample.length;
  const compressedGzBytes = Buffer.from(encodedBitstringSample.slice(1), 'base64url').length;

  const results = {
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      redisServer: '5.0.14.1 (TCP 127.0.0.1:6379)',
      date: new Date().toISOString()
    },
    bitstringStats: {
      totalBits: MIN_LIST_LENGTH,
      rawBytes: rawBitstringBytes,
      gzipCompressedBytes: compressedGzBytes,
      multibaseEncodedLength: encodedBitstringChars,
      compressionRatioPercent: Number(((1 - compressedGzBytes / rawBitstringBytes) * 100).toFixed(2)),
      signedStatusListCredentialBytes: Buffer.byteLength(JSON.stringify(statusListCredSample), 'utf8'),
      encodeMs: stats(tBitstringEncode),
      decodeMs: stats(tBitstringDecode)
    },
    httpApiTimingsMs: {
      issueCredentialApi: stats(tIssueApi),
      verifierCreateRequestApi: stats(tRequestApi),
      walletPreviewApi: stats(tPreviewApi),
      walletPresentSelectiveApi: stats(tPresentApi),
      verifierDirectPostTotalApi: stats(tVerifyTotalApi),
      step1_redisSetNxExMs: stats(tRedisStep),
      step2_ecdsaSdVerifyMs: stats(tCryptoStep),
      step3_bitstringStatusCheckMs: stats(tStatusStep)
    },
    concurrentReplayTest200: {
      totalRequests: 200,
      acceptedHttp200: accepted200,
      rejectedHttp409: rejected409,
      totalBurstDurationMs: Number((c1 - c0).toFixed(2))
    },
    statusCacheMetrics: app.statusCounters
  };

  const outDir = path.resolve(process.cwd(), '.demo-output');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, {recursive: true});
  fs.writeFileSync(path.join(outDir, 'benchmark-week7.json'), JSON.stringify(results, null, 2));
  fs.writeFileSync(path.join(outDir, 'sample-status-list-credential.json'), JSON.stringify(statusListCredSample, null, 2));
  fs.writeFileSync(path.join(outDir, 'sample-openid4vp-presentation.json'), JSON.stringify(lastPresentationSample, null, 2));

  await app.close();
  console.log(JSON.stringify(results, null, 2));
  console.log('\n=== REAL BENCHMARK WEEK 07 HOAN TAT ===');
}

runBenchmark().catch(err => {
  console.error(err);
  process.exit(1);
});
