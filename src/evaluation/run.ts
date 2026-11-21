import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {appendFileSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {cpus, release, totalmem} from 'node:os';
import {resolve} from 'node:path';
import {performance} from 'node:perf_hooks';

export function command(program: string, args: string[]) {
  const result = spawnSync(program, args, {encoding: 'utf8'});
  if(result.status !== 0) throw new Error(`${program} ${args.join(' ')} failed: ${result.stderr || result.error}`);
  return result.stdout.trim();
}

export function count(name: string, fallback: number, minimum = 1) {
  const value = Number(process.env[name] ?? fallback);
  if(!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} must be an integer >= ${minimum}`);
  return value;
}

export function startRun(kind: 'crypto' | 'http', config: object) {
  const output = resolve(process.env.BENCH_OUTPUT ?? '.demo-output/evaluation', kind);
  const node = process.versions;
  const commit = command('git', ['rev-parse', 'HEAD']);
  const dirty = command('git', ['status', '--porcelain']).length > 0;
  const lockSha256 = createHash('sha256').update(readFileSync('package-lock.json')).digest('hex');
  const cpu = cpus();
  const manifest = {
    schema: 1, kind, startedAt: new Date().toISOString(), commit, dirty, lockSha256,
    host: {platform: process.platform, arch: process.arch, release: release(), cpu: cpu[0]?.model,
      logicalCpus: cpu.length, ramBytes: totalmem(), node: node.node, openssl: node.openssl,
      npm: command(process.platform === 'win32' ? 'cmd.exe' : 'npm',
        process.platform === 'win32' ? ['/d', '/c', 'npm --version'] : ['--version'])},
    config
  };
  mkdirSync(resolve(output, '..'), {recursive: true});
  mkdirSync(output);
  writeFileSync(resolve(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  const data = resolve(output, 'samples.jsonl');
  writeFileSync(data, '');
  return {
    sample(row: object) { appendFileSync(data, JSON.stringify(row) + '\n'); },
    finish() {
      writeFileSync(resolve(output, 'manifest.json'),
        JSON.stringify({...manifest, completedAt: new Date().toISOString()}, null, 2) + '\n');
      console.log(output);
    }
  };
}

export const bytes = (value: unknown) => Buffer.byteLength(JSON.stringify(value), 'utf8');

export async function timed<T>(operation: () => Promise<T>): Promise<[T, number]> {
  const start = performance.now();
  const result = await operation();
  return [result, performance.now() - start];
}
