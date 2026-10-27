import * as net from 'node:net';
import {createHash} from 'node:crypto';

// Client RESP toi gian (khong can thu vien ngoai) de goi lenh nguyen tu:
//   SET key 1 NX EX ttl
// Redis xu ly lenh don luong nen chi dung 1 request dau tien ghi duoc khoa.
export class RedisReplayGuard {
  private socket: net.Socket | null = null;
  private buffer = '';
  private queue: Array<(reply: string) => void> = [];

  constructor(private host = '127.0.0.1', private port = 6379, private ttlSeconds = 300) {}

  // Docker: REDIS_HOST=redis-guard, REDIS_PORT=6379
  static fromEnv(ttlSeconds = 300) {
    return new RedisReplayGuard(process.env.REDIS_HOST || '127.0.0.1', Number(process.env.REDIS_PORT) || 6379, ttlSeconds);
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const s = net.createConnection({host: this.host, port: this.port}, () => resolve());
      s.setNoDelay(true);
      s.on('error', reject);
      s.on('data', chunk => this.onData(chunk.toString('utf8')));
      this.socket = s;
    });
  }

  private onData(data: string) {
    this.buffer += data;
    // Chi can xu ly simple string (+OK), null bulk ($-1), integer (:n) va error (-ERR)
    let idx: number;
    while((idx = this.buffer.indexOf('\r\n')) >= 0) {
      const line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 2);
      const cb = this.queue.shift();
      if(cb) cb(line);
    }
  }

  private command(args: string[]): Promise<string> {
    if(!this.socket) throw new Error('chua ket noi Redis');
    let payload = `*${args.length}\r\n`;
    for(const a of args) payload += `$${Buffer.byteLength(a)}\r\n${a}\r\n`;
    return new Promise(resolve => {
      this.queue.push(resolve);
      this.socket!.write(payload);
    });
  }

  // Khoa gan voi ngu canh de nonce khong the mang sang verifier khac
  static keyFor(nonce: string, audience: string) {
    return 'replay:nonce:' + createHash('sha256').update(nonce + '|' + audience).digest('hex');
  }

  // true = lan dau (hop le), false = da dung (replay)
  async consume(nonce: string, audience: string): Promise<boolean> {
    const reply = await this.command(['SET', RedisReplayGuard.keyFor(nonce, audience), '1', 'NX', 'EX', String(this.ttlSeconds)]);
    if(reply.startsWith('-')) throw new Error('Redis loi: ' + reply);
    return reply === '+OK';
  }

  async ttl(nonce: string, audience: string): Promise<number> {
    const reply = await this.command(['TTL', RedisReplayGuard.keyFor(nonce, audience)]);
    return Number(reply.slice(1));
  }

  async flush() {
    await this.command(['FLUSHDB']);
  }

  close() {
    this.socket?.end();
    this.socket = null;
  }
}
