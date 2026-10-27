import {randomBytes, scrypt as scryptCb, timingSafeEqual} from 'node:crypto';

// Bam mat khau bang scrypt (RFC 7914). Dinh dang luu: scrypt$N$r$p$salt$hash (base64url).
const N = 16384, R = 8, P = 1, KEYLEN = 32;

function scrypt(password: string, salt: Buffer, n: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scryptCb(password, salt, KEYLEN, {N: n, r, p, maxmem: 64 * 1024 * 1024}, (err, key) => err ? reject(err) : resolve(key)));
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, N, R, P);
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(password: string, stored: string | undefined): Promise<boolean> {
  if(!stored) return false;
  const [alg, n, r, p, salt, hash] = stored.split('$');
  if(alg !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64url');
  const key = await scrypt(password, Buffer.from(salt, 'base64url'), Number(n), Number(r), Number(p));
  return key.length === expected.length && timingSafeEqual(key, expected);
}

// Chinh sach mat khau toi thieu cho tai khoan tao moi
export function passwordPolicyError(pw: unknown): string | null {
  if(typeof pw !== 'string' || pw.length < 8) return 'Mật khẩu phải có ít nhất 8 ký tự';
  if(!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'Mật khẩu phải gồm cả chữ và số';
  return null;
}
