// Run from the repository: node scripts/compare-wallets.mjs OUTPUT.json
// Invoked against the fresh benchmark Compose project by compare-wallets.ps1.
import assert from 'node:assert/strict';
import {cpus} from 'node:os';
import {execFileSync} from 'node:child_process';
import {writeFileSync} from 'node:fs';
const password = process.env.DEMO_PASSWORD;
const output = process.argv[2];
assert.ok(password && output && process.env.WALLET_BENCH_PROJECT);
const issuer = 'http://localhost:18441', verifier = 'http://localhost:18442', wallet = 'http://localhost:18440';
const samples = [];
async function post(base, path, body, cookie) {
  const res = await fetch(base + path, {method:'POST', headers:{'Content-Type':'application/json', ...(cookie && {Cookie:cookie})},
    body:JSON.stringify(body), signal:AbortSignal.timeout(60000)});
  const data = await res.json();
  if (!res.ok) throw Error(path + ' ' + res.status + ' ' + (data.error ?? data.code));
  return {data, cookie:res.headers.get('set-cookie')?.split(';')[0]};
}
async function present(holder, hr) {
  const start = performance.now();
  try {
    const request = await post(verifier,'/api/verifier/request',{claims:['major']},hr);
    const draft = {request:request.data.request, credentialId:holder.id};
    const preview = await post(wallet,'/api/wallet/preview',draft,holder.cookie);
    const response = await post(wallet,'/api/wallet/present',{...draft,approvedClaims:['major'],consentId:preview.data.consentId,consent:true,submit:true},holder.cookie);
    const result = response.data.submitted;
    assert.equal(result.status,200);
    assert.equal(result.body.verified,true);
    assert.deepEqual(Object.keys(result.body.disclosed).sort(),['graduated','id','major','studentName']);
    assert.equal(result.body.disclosed.studentName,holder.name);
    return {ok:true,ms:performance.now()-start};
  } catch (error) {return {ok:false,ms:performance.now()-start,error:String(error)};}
}
async function main() {
  const login = async username => (await post(issuer,'/api/portal/auth/login',{username,password})).cookie;
  const registrar = await login('chuyenvien'), approver = await login('truongphong');
  const hr = (await post(verifier,'/api/rp/auth/login',{username:'hr.fpt',password})).cookie;
  const holders = [];
  for (let i=0; i<50; i++) {
    const code = String(89000000+i), email = code+'@vnu.edu.vn', name = 'Benchmark '+code;
    await post(issuer,'/api/portal/students',{studentCode:code,email,fullName:name,nationalId:String(890000000000+i),
      major:'IT',degreeName:'Bachelor',status:'GRADUATED',graduationDate:'2026-06-30',gpa:'3.50',classification:'Good'},registrar);
    const record = await post(issuer,'/api/portal/records',{studentCode:code,kind:'degree'},registrar);
    const id = record.data.record.id;
    await post(issuer,'/api/portal/records/'+id+'/approve',{note:'Synthetic benchmark'},approver);
    const session = await post(wallet,'/api/wallet-portal/auth/login',{method:'sso',identifier:email,password});
    const claim = await post(wallet,'/api/wallet-portal/claim',{recordId:id},session.cookie);
    holders.push({id,name,cookie:session.cookie,did:claim.data.credential.credentialSubject.id});
  }
  assert.ok(holders.every(holder=>typeof holder.did==='string' && holder.did.startsWith('did:')));
  assert.equal(new Set(holders.map(h=>h.did)).size,50);
  for (const holder of holders) assert.ok((await present(holder,hr)).ok,'warmup');
  for (let block=0; block<10; block++) {
    for (const mode of block%2 ? ['distributed','shared'] : ['shared','distributed']) {
      const rows = await Promise.all(holders.map((h,lane)=>present(mode==='shared'?holders[block]:h,hr)
        .then(row=>({block,mode,lane,...row}))));
      samples.push(...rows);
      console.log(block,mode,rows.filter(row=>row.ok).length);
    }
  }
  const summary = {};
  for (const mode of ['shared','distributed']) {
    const group = samples.filter(row=>row.mode===mode);
    const times = group.filter(row=>row.ok).map(row=>row.ms).sort((a,b)=>a-b);
    const n = times.length;
    summary[mode] = {attempts:group.length,success:n,errors:group.length-n,
      medianMs:n?(times[Math.floor((n-1)/2)]+times[Math.floor(n/2)])/2:null,
      p95Ms:n?times[Math.ceil(n*.95)-1]:null};
  }
  writeFileSync(output,JSON.stringify({commit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),
    node:process.version,cpu:cpus()[0].model,backend:'Docker Compose / PostgreSQL / Redis / HTTP loopback', summary,
    distinctHolders:50,warmup:50,samples},null,2),{flag:'wx'});
  console.table(summary);
}
await main();
