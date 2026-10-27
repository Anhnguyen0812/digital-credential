import {writeFileSync, mkdirSync} from 'node:fs';
import {performance} from 'node:perf_hooks';
import {gunzipSync} from 'node:zlib';
import * as vc from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as rdfcCryptosuite} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {createVerifyCryptosuite as createSdVerifySuite} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {initializeIdentities} from './crypto/multikey-manager.js';
import {createCustomDocumentLoader} from './context/document-loader.js';
import {
  issueSelectiveDisclosureVc, issueFullDisclosureVc, deriveVc, signPresentationWithHolder, verifyBoundPresentation
} from './crypto/holder-binding.js';
import {BitstringStatusList} from './status/bitstring-status.js';
import {EDUCATION_CONTEXT_URL} from './context/education-v1.js';
import {buildUnsignedDegreeVc, DEGREE_MANDATORY_POINTERS, DEGREE_SELECTIVE_MAP} from './profiles/degree-profile.js';

const WARMUP = 5;
const ITER = Number(process.env.BENCH_ITER) || 30;
const AUD = 'redirect_uri:http://verifier.example/direct-post';

function stats(samples: number[]) {
  const s = [...samples].sort((a, b) => a - b);
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  const sd = Math.sqrt(samples.reduce((a, b) => a + (b - mean) ** 2, 0) / samples.length);
  const q = (p: number) => s[Math.min(s.length - 1, Math.floor(s.length * p))];
  const r = (x: number) => Number(x.toFixed(3));
  return {min: r(s[0]), median: r(q(0.5)), mean: r(mean), stdev: r(sd), p95: r(q(0.95)), max: r(s[s.length - 1])};
}

// PRNG tat dinh (mulberry32) de tai lap ket qua Bernoulli
function prng(seed: number) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const shannon = (p: number) => (p <= 0 || p >= 1 ? 0 : -p * Math.log2(p) - (1 - p) * Math.log2(1 - p));
const bytes = (o: any) => Buffer.byteLength(JSON.stringify(o), 'utf8');

async function timed<T>(fn: () => Promise<T>): Promise<[T, number]> {
  const t = performance.now(); const v = await fn(); return [v, performance.now() - t];
}

async function main() {
  const ids = await initializeIdentities();
  const {issuerKeyPair, holderKeyPair, registry} = ids;
  const documentLoader = createCustomDocumentLoader(registry);
  const env = {generatedAt: new Date().toISOString(), node: process.version, platform: `${process.platform}-${process.arch}`, warmup: WARMUP, iterations: ITER};

  // ===== THUC NGHIEM 1 (TSK-01): scaling theo n va ty le tiet lo k/n =====
  async function runScaling(n: number, k: number) {
    const extraClaims: Record<string, string> = {};
    const pointers: string[] = [];
    for(let i = 0; i < n; i++) { extraClaims[`claim_${i}`] = `Gia tri hoc tap thuoc tinh so ${i} cua sinh vien UET`; pointers.push(`/credentialSubject/extraClaims/claim_${i}`); }
    const chosen = pointers.slice(0, k);
    const unsigned = {
      '@context': ['https://www.w3.org/ns/credentials/v2', EDUCATION_CONTEXT_URL],
      type: ['VerifiableCredential', 'DegreeCredential'],
      issuer: issuerKeyPair.controller,
      validFrom: '2026-10-01T00:00:00Z',
      credentialSubject: {id: holderKeyPair.controller, studentName: 'Nguyễn Phi Anh', graduated: true, extraClaims}
    };
    const mandatory = ['/issuer', '/validFrom', '/credentialSubject/id', '/credentialSubject/studentName'];
    const issueT: number[] = [], deriveT: number[] = [], signT: number[] = [], verifyT: number[] = [];
    let baseSize = 0, vpSize = 0;
    for(let r = -WARMUP; r < ITER; r++) {
      const [base, ti] = await timed(() => issueSelectiveDisclosureVc({unsignedCredential: unsigned, issuerKeyPair, mandatoryPointers: mandatory, documentLoader}));
      const [derived, td] = await timed(() => deriveVc({baseCredential: base, selectivePointers: chosen, documentLoader}));
      const nonce = `n-${n}-${k}-${r}`;
      const [vp, ts] = await timed(() => signPresentationWithHolder({derivedVc: derived, holderKeyPair, nonce, audience: AUD, documentLoader}));
      const [res, tv] = await timed(() => verifyBoundPresentation({verifiablePresentation: vp, expectedNonce: nonce, expectedAudience: AUD, documentLoader}));
      if(!res.verified) throw new Error('benchmark verify failed: ' + JSON.stringify(res.detail ?? res.reason));
      if(r >= 0) {
        issueT.push(ti); deriveT.push(td); signT.push(ts); verifyT.push(tv);
        if(r === 0) { baseSize = bytes(base); vpSize = bytes(vp); }
      }
    }
    return {n, k, ratio: Number((k / n).toFixed(2)), baseSizeBytes: baseSize, vpSizeBytes: vpSize,
      issueMs: stats(issueT), deriveMs: stats(deriveT), holderSignMs: stats(signT), verifyMs: stats(verifyT)};
  }

  console.log('Thuc nghiem 1a: scaling theo n (k = n/2)');
  const scalingN = [];
  for(const n of [5, 10, 20, 50, 100]) { scalingN.push(await runScaling(n, Math.max(1, Math.floor(n / 2)))); console.log('  n =', n); }
  console.log('Thuc nghiem 1b: ty le tiet lo k/n (n = 50)');
  const scalingK = [];
  for(const pct of [0.1, 0.25, 0.5, 0.75, 1]) { scalingK.push(await runScaling(50, Math.max(1, Math.round(50 * pct)))); console.log('  k/n =', pct); }

  // ===== THUC NGHIEM 2 (TSK-03): nen GZIP Bitstring theo Bernoulli/Entropy =====
  console.log('Thuc nghiem 2: Bitstring entropy');
  const entropy: any[] = [];
  for(const bits of [131_072, 1_048_576]) {
    for(const p of [0, 0.00001, 0.0001, 0.001, 0.01, 0.05, 0.1, 0.2]) {
      const rnd = prng(20261027 + bits);
      const list = new BitstringStatusList(bits);
      let ones = 0;
      for(let i = 0; i < bits; i++) if(rnd() < p) { list.set(i, true); ones++; }
      const encT: number[] = [], decT: number[] = [];
      let encoded = '';
      for(let r = 0; r < ITER; r++) {
        let t = performance.now(); encoded = list.encode(); encT.push(performance.now() - t);
        t = performance.now(); BitstringStatusList.decode(encoded); decT.push(performance.now() - t);
      }
      const gz = Buffer.from(encoded.slice(1), 'base64url');
      const rawBytes = bits / 8;
      const H = shannon(ones / bits);
      entropy.push({
        bits, revocationRate: p, revokedCount: ones, shannonH: Number(H.toFixed(5)),
        theoreticalMinBytes: Math.ceil((H * bits) / 8), rawBytes, gzipBytes: gz.length,
        multibaseChars: encoded.length, gunzipOk: gunzipSync(gz).length === rawBytes,
        compressionRatioPercent: Number(((1 - gz.length / rawBytes) * 100).toFixed(2)),
        encodeMs: stats(encT), decodeMs: stats(decT)
      });
    }
  }

  // ===== THUC NGHIEM 3 (TSK-02): ecdsa-sd-2023 vs Baseline Full Disclosure ecdsa-rdfc-2019 =====
  console.log('Thuc nghiem 3: SD vs baseline');
  const unsignedDegree = buildUnsignedDegreeVc({holderDid: holderKeyPair.controller, statusListIndex: 1, statusListUrl: 'https://university.edu.vn/status/1', issuerDid: issuerKeyPair.controller});
  const totalClaims = Object.keys(unsignedDegree.credentialSubject).filter(k => k !== 'id').length;
  const sdChosen = [DEGREE_SELECTIVE_MAP.major];
  const disclosedSd = 2 /* studentName, graduated bat buoc */ + sdChosen.length;
  const sdIssue: number[] = [], sdDerive: number[] = [], sdVerifyVc: number[] = [], sdVerifyVp: number[] = [];
  const fdIssue: number[] = [], fdVerify: number[] = [];
  let sdBaseSize = 0, sdDerivedSize = 0, fdSize = 0;
  for(let r = -WARMUP; r < ITER; r++) {
    const [fd, t1] = await timed(() => issueFullDisclosureVc({unsignedCredential: unsignedDegree, issuerKeyPair, documentLoader}));
    const [fdRes, t2] = await timed(() => vc.verifyCredential({credential: fd, suite: new DataIntegrityProof({cryptosuite: rdfcCryptosuite}), documentLoader, checkStatus: async () => ({verified: true})}));
    const [base, t3] = await timed(() => issueSelectiveDisclosureVc({unsignedCredential: unsignedDegree, issuerKeyPair, mandatoryPointers: DEGREE_MANDATORY_POINTERS, documentLoader}));
    const [derived, t4] = await timed(() => deriveVc({baseCredential: base, selectivePointers: sdChosen, documentLoader}));
    const [sdRes, t5] = await timed(() => vc.verifyCredential({credential: derived, suite: new DataIntegrityProof({cryptosuite: createSdVerifySuite()}), documentLoader, checkStatus: async () => ({verified: true})}));
    const nonce = `cmp-${r}`;
    const vp = await signPresentationWithHolder({derivedVc: derived, holderKeyPair, nonce, audience: AUD, documentLoader});
    const [vpRes, t6] = await timed(() => verifyBoundPresentation({verifiablePresentation: vp, expectedNonce: nonce, expectedAudience: AUD, documentLoader}));
    if(!(fdRes as any).verified || !(sdRes as any).verified || !vpRes.verified) throw new Error('baseline comparison failed');
    if(r >= 0) {
      fdIssue.push(t1); fdVerify.push(t2); sdIssue.push(t3); sdDerive.push(t4); sdVerifyVc.push(t5); sdVerifyVp.push(t6);
      if(r === 0) { fdSize = bytes(fd); sdBaseSize = bytes(base); sdDerivedSize = bytes(derived); }
    }
  }
  const baseline = {
    totalSubjectClaims: totalClaims, disclosedClaimsSd: disclosedSd,
    piiReductionPercent: Number(((1 - disclosedSd / totalClaims) * 100).toFixed(2)),
    fullDisclosure_ecdsaRdfc2019: {issueMs: stats(fdIssue), verifyMs: stats(fdVerify), vcSizeBytes: fdSize},
    selectiveDisclosure_ecdsaSd2023: {
      issueMs: stats(sdIssue), deriveMs: stats(sdDerive), verifyDerivedVcMs: stats(sdVerifyVc),
      verifyBoundVpMs: stats(sdVerifyVp), baseSizeBytes: sdBaseSize, derivedSizeBytes: sdDerivedSize
    },
    issueOverheadMsMedian: Number((stats(sdIssue).median - stats(fdIssue).median).toFixed(3)),
    verifyOverheadMsMedian: Number((stats(sdVerifyVc).median - stats(fdVerify).median).toFixed(3))
  };

  const output = {env, experiment1a_claimScaling: scalingN, experiment1b_disclosureRatio: scalingK, experiment2_bitstringEntropy: entropy, experiment3_baseline: baseline};
  mkdirSync('.demo-output', {recursive: true});
  writeFileSync('.demo-output/final-benchmark-week8.json', JSON.stringify(output, null, 2), 'utf8');
  writeFileSync('.demo-output/scaling-benchmark.json', JSON.stringify({env, experiment1a_claimScaling: scalingN, experiment1b_disclosureRatio: scalingK}, null, 2), 'utf8');

  const md: string[] = [`# Benchmark Tuan 8 (${env.node}, ${env.platform}, warm-up ${WARMUP}, ${ITER} vong)`, ''];
  md.push('## TN1a - Scaling theo n (k = n/2), don vi ms (median / p95)', '', '| n | k | issue | derive | holder sign | verify (VP+VC) | base VC (B) | VP (B) |', '|---|---|---|---|---|---|---|---|');
  for(const r of scalingN) md.push(`| ${r.n} | ${r.k} | ${r.issueMs.median} / ${r.issueMs.p95} | ${r.deriveMs.median} / ${r.deriveMs.p95} | ${r.holderSignMs.median} / ${r.holderSignMs.p95} | ${r.verifyMs.median} / ${r.verifyMs.p95} | ${r.baseSizeBytes} | ${r.vpSizeBytes} |`);
  md.push('', '## TN1b - Ty le tiet lo k/n (n = 50)', '', '| k/n | k | derive median | verify median | VP (B) |', '|---|---|---|---|---|');
  for(const r of scalingK) md.push(`| ${r.ratio * 100}% | ${r.k} | ${r.deriveMs.median} | ${r.verifyMs.median} | ${r.vpSizeBytes} |`);
  md.push('', '## TN2 - GZIP Bitstring theo ty le thu hoi p va Entropy Shannon H(p)', '', '| bits | p | so bit 1 | H(p) | min ly thuyet (B) | GZIP (B) | nen % | decode median ms |', '|---|---|---|---|---|---|---|---|');
  for(const r of entropy) md.push(`| ${r.bits} | ${(r.revocationRate * 100).toFixed(3)}% | ${r.revokedCount} | ${r.shannonH} | ${r.theoreticalMinBytes} | ${r.gzipBytes} | ${r.compressionRatioPercent} | ${r.decodeMs.median} |`);
  md.push('', '## TN3 - ecdsa-sd-2023 vs Baseline Full Disclosure (ecdsa-rdfc-2019)', '',
    `PII giam: ${baseline.piiReductionPercent}% (${disclosedSd}/${totalClaims} claim duoc tiet lo). Overhead issue +${baseline.issueOverheadMsMedian} ms, verify VC ${baseline.verifyOverheadMsMedian >= 0 ? '+' : ''}${baseline.verifyOverheadMsMedian} ms (median).`, '',
    '| Phuong an | issue median | derive median | verify median | kich thuoc (B) |', '|---|---|---|---|---|',
    `| Full Disclosure rdfc-2019 | ${baseline.fullDisclosure_ecdsaRdfc2019.issueMs.median} | - | ${baseline.fullDisclosure_ecdsaRdfc2019.verifyMs.median} | ${fdSize} |`,
    `| SD-2023 (derived VC) | ${baseline.selectiveDisclosure_ecdsaSd2023.issueMs.median} | ${baseline.selectiveDisclosure_ecdsaSd2023.deriveMs.median} | ${baseline.selectiveDisclosure_ecdsaSd2023.verifyDerivedVcMs.median} | ${sdDerivedSize} |`);
  writeFileSync('.demo-output/final-benchmark-week8.md', md.join('\n'), 'utf8');
  console.log('Da xuat .demo-output/final-benchmark-week8.json, scaling-benchmark.json, final-benchmark-week8.md');
}

main().catch(e => { console.error(e); process.exit(1); });
