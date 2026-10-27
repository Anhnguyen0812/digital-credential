import * as path from 'node:path';
import * as fs from 'node:fs';
import {performance} from 'node:perf_hooks';
import {makeIssuerSetup} from './issuer-setup.js';
import {
  issueLegacyDegree,
  discloseLegacyDegree,
  verifyDegree
} from './credential-service.js';
import {StatusStore} from './status-store.js';
import {
  createOrGetSampleScanFile,
  computeFileDigest,
  generateApproverKeyPair,
  buildLegacyProvenance,
  signApproverAction
} from './legacy-service.js';
import type {DegreeInput} from './types.js';

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

async function runBenchmark() {
  console.log('=== KHOA LUAN WEEK 06 REAL BENCHMARK ===');
  const setup = await makeIssuerSetup();
  const approverKeys = generateApproverKeyPair();

  const testVectorsDir = path.resolve(process.cwd(), 'test-vectors');
  const scanFilePath = path.join(testVectorsDir, 'sample_ledger_2015.bin');
  createOrGetSampleScanFile(scanFilePath, 2_400_000); // 2.4 MB

  const legacyInput: DegreeInput = {
    id: 'urn:uuid:legacy-degree-2015-0842',
    statusIndex: 42,
    subject: {
      id: 'did:key:z6MkuLearnerWalletKey2026',
      studentName: 'Nguyễn Phi Anh',
      studentCode: '23020009',
      degreeName: 'Cử nhân Công nghệ thông tin',
      major: 'Công nghệ thông tin',
      graduationDate: '2015-06-25',
      gpa: 3.65,
      classification: 'Xuất sắc',
      graduated: true,
      legacyProvenance: buildLegacyProvenance({
        scanFilePath,
        studentCode: '23020009',
        registryBookNumber: 'BK-2015/0842',
        originalIssueDate: '2015-06-25',
        degreeSerial: 'B15-004921',
        verifiedBy: 'nv_daotao_01',
        approvedBy: 'truongphong_daotao_01',
        approverPrivateKeyPem: approverKeys.privateKey
      })
    }
  };

  const store = new StatusStore();
  const rounds = 30;
  const warmup = 5;

  const tHash: number[] = [];
  const tSignApprover: number[] = [];
  const tIssueVc: number[] = [];
  const tDiscloseVc: number[] = [];
  const tVerifyVc: number[] = [];

  let sampleBaseVc: any = null;
  let sampleDerivedVc: any = null;

  for (let i = 0; i < warmup + rounds; i++) {
    const isWarmup = i < warmup;

    // 1. Hash 2.4MB scan file
    const h0 = performance.now();
    const digest = computeFileDigest(scanFilePath);
    const h1 = performance.now();
    if (!isWarmup) tHash.push(h1 - h0);

    // 2. Sign approver
    const a0 = performance.now();
    signApproverAction({
      studentCode: '23020009',
      registryBookNumber: 'BK-2015/0842',
      originalIssueDate: '2015-06-25',
      sourceDocumentDigest: digest
    }, approverKeys.privateKey);
    const a1 = performance.now();
    if (!isWarmup) tSignApprover.push(a1 - a0);

    // 3. Issue Base VC
    const i0 = performance.now();
    const baseVc = await issueLegacyDegree(legacyInput, setup);
    const i1 = performance.now();
    if (!isWarmup) tIssueVc.push(i1 - i0);

    // 4. Disclose Derived VC
    const d0 = performance.now();
    const derivedVc = await discloseLegacyDegree(baseVc, setup);
    const d1 = performance.now();
    if (!isWarmup) tDiscloseVc.push(d1 - d0);

    // 5. Verify Derived VC
    const v0 = performance.now();
    const vResult = await verifyDegree(derivedVc, setup, store);
    const v1 = performance.now();
    if (!isWarmup) tVerifyVc.push(v1 - v0);

    if (i === warmup + rounds - 1) {
      sampleBaseVc = baseVc;
      sampleDerivedVc = derivedVc;
    }
  }

  const baseSize = Buffer.byteLength(JSON.stringify(sampleBaseVc), 'utf8');
  const derivedSize = Buffer.byteLength(JSON.stringify(sampleDerivedVc), 'utf8');

  const results = {
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      date: new Date().toISOString()
    },
    sampleData: {
      scanFileSize: fs.statSync(scanFilePath).size,
      sourceDocumentDigest: computeFileDigest(scanFilePath),
      registryBookNumber: 'BK-2015/0842',
      degreeSerial: 'B15-004921'
    },
    timingStatsMs: {
      hashScanFile2_4MB: stats(tHash),
      signApproverAction: stats(tSignApprover),
      issueLegacyBaseVc: stats(tIssueVc),
      discloseDerivedVc: stats(tDiscloseVc),
      verifyDerivedVc: stats(tVerifyVc)
    },
    payloadSizesBytes: {
      baseVc: baseSize,
      derivedVc: derivedSize,
      reductionBytes: baseSize - derivedSize,
      reductionPercent: Number(((baseSize - derivedSize) / baseSize * 100).toFixed(2))
    }
  };

  const outDir = path.resolve(process.cwd(), '.demo-output');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, {recursive: true});

  fs.writeFileSync(path.join(outDir, 'benchmark-week6.json'), JSON.stringify(results, null, 2));
  fs.writeFileSync(path.join(outDir, 'sample-legacy-base-vc.json'), JSON.stringify(sampleBaseVc, null, 2));
  fs.writeFileSync(path.join(outDir, 'sample-legacy-derived-vc.json'), JSON.stringify(sampleDerivedVc, null, 2));

  console.log(JSON.stringify(results, null, 2));
  console.log('\n=== REAL BENCHMARK HOAN TAT. Saved to .demo-output/benchmark-week6.json ===');
}

runBenchmark().catch(console.error);
