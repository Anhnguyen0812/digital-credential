import {mkdir, writeFile} from 'node:fs/promises';
import {performance} from 'node:perf_hooks';
import {makeIssuerSetup} from './issuer-setup.js';
import {discloseDegree, issueDegree, verifyDegree} from './credential-service.js';
import {StatusStore} from './status-store.js';
import {makePresentation, ReplayGuard, verifyPresentation} from './presentation.js';
import {sampleInput} from './sample.js';
import {VERIFY_AUDIENCE} from './config.js';

function ms(n: number) {
  return Math.round(n * 100) / 100;
}

async function main() {
  const setup = await makeIssuerSetup();
  const store = new StatusStore();

  let t = performance.now();
  const signed = await issueDegree(sampleInput, setup);
  const issueMs = performance.now() - t;

  t = performance.now();
  const disclosed = await discloseDegree(signed, setup);
  const discloseMs = performance.now() - t;

  t = performance.now();
  const checked = await verifyDegree(disclosed, setup, store);
  const verifyMs = performance.now() - t;

  const req = {nonce: 'week4-nonce-001', audience: VERIFY_AUDIENCE};
  const vp = makePresentation(disclosed, req);
  const guard = new ReplayGuard();
  const first = await verifyPresentation(vp, req, guard, setup, store);
  const replay = await verifyPresentation(vp, req, guard, setup, store);

  await mkdir('.demo-output', {recursive: true});
  await writeFile('.demo-output/signed-degree.json', JSON.stringify(signed, null, 2));
  await writeFile('.demo-output/disclosed-degree.json', JSON.stringify(disclosed, null, 2));
  await writeFile('.demo-output/presentation.json', JSON.stringify(vp, null, 2));

  console.log('=== WEEK 04 DEMO ===');
  console.log('Issue:', ms(issueMs), 'ms');
  console.log('Disclose:', ms(discloseMs), 'ms');
  console.log('Verify:', ms(verifyMs), 'ms');
  console.log('Credential valid:', checked.verified);
  console.log('Disclosed fields:', Object.keys(disclosed.credentialSubject));
  console.log('GPA hidden:', disclosed.credentialSubject.gpa === undefined);
  console.log('First presentation valid:', first.verified);
  console.log('Replay blocked:', replay.verified === false);
  console.log('Output saved to .demo-output/');
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
