import {createHmac, timingSafeEqual} from 'node:crypto';

// Verification Receipt Token: Verifier cap sau khi vuot qua toan bo buoc xac minh,
// Issuer kiem tra (HMAC, secret dung chung) truoc khi tra ban scan so goc co dong dau mo.
export interface ReceiptClaims {
  aud: string;      // ten don vi tuyen dung (hien thi tren watermark)
  digest?: string;  // sourceDocumentDigest duoc phep truy xuat
  exp: number;      // epoch seconds
}

const secret = () => process.env.RECEIPT_SECRET || 'dev-receipt-secret-change-me';

export function signReceipt(claims: ReceiptClaims): string {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const mac = createHmac('sha256', secret()).update(payload).digest('base64url');
  return `${payload}.${mac}`;
}

export function verifyReceipt(token: string | undefined): ReceiptClaims | null {
  if(!token) return null;
  const [payload, mac] = token.split('.');
  if(!payload || !mac) return null;
  const expected = createHmac('sha256', secret()).update(payload).digest();
  const given = Buffer.from(mac, 'base64url');
  if(given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as ReceiptClaims;
    return claims.exp * 1000 > Date.now() ? claims : null;
  } catch { return null; }
}
