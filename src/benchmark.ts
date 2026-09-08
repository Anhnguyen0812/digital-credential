import {mkdir, writeFile} from 'node:fs/promises';
import {performance} from 'node:perf_hooks';
import {makeIssuerSetup} from './issuer-setup.js';
import {discloseDegree, issueDegree, makeUnsignedDegree, verifyDegree} from './credential-service.js';
import {StatusStore} from './status-store.js';
import {sampleInput} from './sample.js';

function getStats(list: number[]) {
  const a = [...list].sort((x, y) => x - y);
  const mid = Math.floor(a.length / 2);
  const median = a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
  const p95 = a[Math.ceil(a.length * 0.95) - 1];
  const fix = (n: number) => Math.round(n * 100) / 100;
  return {min: fix(a[0]), median: fix(median), p95: fix(p95), max: fix(a[a.length - 1])};
}

async function one(setup: any, store: StatusStore) {
  let t = performance.now();
  const signed = await issueDegree(sampleInput, setup);
  const issue = performance.now() - t;

  t = performance.now();
  const disclosed = await discloseDegree(signed, setup);
  const disclose = performance.now() - t;

  t = performance.now();
  const rs = await verifyDegree(disclosed, setup, store);
  const verify = performance.now() - t;
  if(!rs.verified) throw new Error('Benchmark verification failed');

  return {issue, disclose, verify, signed, disclosed};
}

async function main() {
  const setup = await makeIssuerSetup();
  const store = new StatusStore();

  for(let i = 0; i < 5; i++) await one(setup, store);

  const issue: number[] = [];
  const disclose: number[] = [];
  const verify: number[] = [];
  let last: any;

  for(let i = 0; i < 30; i++) {
    last = await one(setup, store);
    issue.push(last.issue);
    disclose.push(last.disclose);
    verify.push(last.verify);
  }

  const unsignedSize = Buffer.byteLength(JSON.stringify(makeUnsignedDegree(sampleInput)));
  const signedSize = Buffer.byteLength(JSON.stringify(last.signed));
  const disclosedSize = Buffer.byteLength(JSON.stringify(last.disclosed));
  const result = {
    createdAt: new Date().toISOString(),
    node: process.version,
    warmupRuns: 5,
    measureRuns: 30,
    timesMs: {
      issue: getStats(issue),
      disclose: getStats(disclose),
      verifyDerived: getStats(verify)
    },
    sizesBytes: {
      unsigned: unsignedSize,
      signed: signedSize,
      disclosed: disclosedSize,
      disclosedVsSignedPercent: Math.round(disclosedSize / signedSize * 10000) / 100
    }
  };

  await mkdir('.demo-output', {recursive: true});
  await writeFile('.demo-output/benchmark.json', JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
  console.log('Saved benchmark results to .demo-output/benchmark.json');
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
