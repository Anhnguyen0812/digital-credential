import * as net from 'node:net';
import {createHash} from 'node:crypto';

// Client RESP toi gian (khong can thu vien ngoai) de goi lenh nguyen tu:
//   SET key 1 NX EX ttl
// Redis xu ly lenh don luong nen chi dung 1 request dau tien ghi duoc khoa.
export class RedisReplayGuard {
  private socket: net.Socket | null = null;
  private buffer = '';
  private queue: Array<{resolve: (reply: string) => void; reject: (error: Error) => void}> = [];

  constructor(private host = '127.0.0.1', private port = 6379, private ttlSeconds = 300) {}

  // Docker: REDIS_HOST=redis-guard, REDIS_PORT=6379
  static fromEnv(ttlSeconds = 300) {
    return new RedisReplayGuard(process.env.REDIS_HOST || '127.0.0.1', Number(process.env.REDIS_PORT) || 6379, ttlSeconds);
  }

  private unavailable() {
    return Object.assign(new Error('Redis không khả dụng'), {status: 503});
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({host: this.host, port: this.port}, () => {
        clearTimeout(timeout);
        resolve();
      });
      const timeout = setTimeout(() => socket.destroy(this.unavailable()), 3000);
      const disconnected = () => {
        clearTimeout(timeout);
        const error = this.unavailable();
        reject(error);
        if(this.socket !== socket) return;
        this.socket = null;
        this.buffer = '';
        for(const command of this.queue.splice(0)) command.reject(error);
      };
      socket.setNoDelay(true);
      socket.on('error', disconnected);
      socket.on('close', disconnected);
      socket.on('data', chunk => this.onData(chunk.toString('utf8')));
      this.socket = socket;
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
      cb?.resolve(line);
    }
  }

  private command(args: string[]): Promise<string> {
    const socket = this.socket;
    if(!socket || socket.destroyed) return Promise.reject(this.unavailable());
    let payload = '*' + args.length + '\r\n';
    for(const arg of args) payload += '$' + Buffer.byteLength(arg) + '\r\n' + arg + '\r\n';
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => socket.destroy(this.unavailable()), 3000);
      this.queue.push({
        resolve: reply => { clearTimeout(timeout); resolve(reply); },
        reject: error => { clearTimeout(timeout); reject(error); }
      });
      socket.write(payload);
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
    this.socket?.destroy();
  }
}
