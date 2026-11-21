import {createHash} from 'node:crypto';

const subtle = globalThis.crypto.subtle;

export interface OidcIdTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  auth_time: number;
  acr: 'urn:vnu:sso:loa1' | 'urn:gov:vn:vneid:loa2';
  amr: string[];
  student_code: string;
  full_name: string;
  email?: string;
  national_id?: string;
}

/**
 * Mô-đun Nhà cung cấp Định danh chuẩn OpenID Connect (OIDC) & VNeID (W9-05).
 * Học tập từ kiến trúc MIT Learner Credential Wallet & Cổng NARIC tích hợp VNeID:
 * - Ký số id_token chuẩn JWT (alg: ES256 trên đường cong P-256) bằng WebCrypto API.
 * - Công bố /.well-known/openid-configuration và /.well-known/jwks.json để Ví / Relying Party kiểm chứng độc lập.
 * - Hỗ trợ sinh khóa P-256 không trích xuất được (extractable: false) bằng WebCrypto SubtleCrypto.
 */
export class OidcIdentityProvider {
  private privateKey!: CryptoKey;
  private publicKey!: CryptoKey;
  private publicJwk!: JsonWebKey & {kid: string; use: string; alg: string};
  get kid() { return this.publicJwk.kid; }

  private constructor(readonly issuerUrl: string) {}

  static async create(issuerUrl: string): Promise<OidcIdentityProvider> {
    const idp = new OidcIdentityProvider(issuerUrl);
    const kp = await subtle.generateKey(
      {name: 'ECDSA', namedCurve: 'P-256'},
      false, // Khóa bí mật không thể bị xuất ra ngoài (non-extractable)
      ['sign', 'verify']
    );
    idp.privateKey = kp.privateKey;
    idp.publicKey = kp.publicKey;
    const jwk = (await subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey;
    idp.publicJwk = {
      ...jwk,
      kid: createHash('sha256').update(JSON.stringify([jwk.x, jwk.y])).digest('base64url').slice(0, 24),
      use: 'sig',
      alg: 'ES256'
    };
    return idp;
  }

  getDiscoveryMetadata() {
    return {
      issuer: this.issuerUrl,
      authorization_endpoint: `${this.issuerUrl}/api/student-auth/login`,
      token_endpoint: `${this.issuerUrl}/api/student-auth/login`,
      jwks_uri: `${this.issuerUrl}/.well-known/jwks.json`,
      id_token_signing_alg_values_supported: ['ES256'],
      subject_types_supported: ['public'],
      acr_values_supported: ['urn:vnu:sso:loa1', 'urn:gov:vn:vneid:loa2'],
      claims_supported: ['sub', 'iss', 'aud', 'acr', 'amr', 'student_code', 'full_name', 'email', 'national_id']
    };
  }

  getJwks() {
    return {keys: [this.publicJwk]};
  }

  async issueIdToken(params: {
    studentCode: string;
    fullName: string;
    email?: string;
    nationalId?: string;
    method: 'sso' | 'vneid';
    audience?: string;
    ttlSeconds?: number;
  }): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const header = {alg: 'ES256', typ: 'JWT', kid: this.kid};
    const payload: OidcIdTokenClaims = {
      iss: this.issuerUrl,
      sub: `student:${params.studentCode}`,
      aud: params.audience || 'wallet',
      iat: now,
      exp: now + (params.ttlSeconds ?? 7200),
      auth_time: now,
      acr: params.method === 'vneid' ? 'urn:gov:vn:vneid:loa2' : 'urn:vnu:sso:loa1',
      amr: params.method === 'vneid' ? ['vneid_cccd', 'otp_level2'] : ['vnu_sso', 'pwd'],
      student_code: params.studentCode,
      full_name: params.fullName,
      email: params.email,
      national_id: params.nationalId
    };

    const encHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signingInput = `${encHeader}.${encPayload}`;
    const sigBuf = await subtle.sign(
      {name: 'ECDSA', hash: 'SHA-256'},
      this.privateKey,
      new TextEncoder().encode(signingInput)
    );
    const encSig = Buffer.from(sigBuf).toString('base64url');
    return `${signingInput}.${encSig}`;
  }

  async verifyIdToken(idToken: string): Promise<OidcIdTokenClaims | null> {
    try {
      const parts = idToken.split('.');
      if (parts.length !== 3) return null;
      const [encHeader, encPayload, encSig] = parts;
      const header = JSON.parse(Buffer.from(encHeader, 'base64url').toString('utf8'));
      if(header.alg !== 'ES256' || header.kid !== this.kid) return null;
      const signingInput = `${encHeader}.${encPayload}`;
      const sigBuf = Buffer.from(encSig, 'base64url');
      const ok = await subtle.verify(
        {name: 'ECDSA', hash: 'SHA-256'},
        this.publicKey,
        sigBuf,
        new TextEncoder().encode(signingInput)
      );
      if (!ok) return null;
      const claims = JSON.parse(Buffer.from(encPayload, 'base64url').toString('utf8')) as OidcIdTokenClaims;
      if(claims.iss !== this.issuerUrl || claims.aud !== 'wallet' || typeof claims.sub !== 'string' ||
        !Number.isInteger(claims.exp) || claims.exp * 1000 <= Date.now() ||
        !Number.isInteger(claims.iat) || claims.iat * 1000 > Date.now() + 5000) return null;
      return claims;
    } catch {
      return null;
    }
  }
}

/**
 * Minh họa tạo và ký Proof-of-Possession / Holder Attestation bằng WebCrypto API
 * với khóa bí mật không thể trích xuất (extractable: false) như trên trình duyệt hiện đại.
 */
export async function createWebCryptoNonExtractableProof(challenge: string, audience: string) {
  const kp = await subtle.generateKey(
    {name: 'ECDSA', namedCurve: 'P-256'},
    false, // Non-extractable private key in WebCrypto
    ['sign', 'verify']
  );
  const publicJwk = await subtle.exportKey('jwk', kp.publicKey);
  const payload = `webcrypto-pop|${challenge}|${audience}`;
  const sig = await subtle.sign(
    {name: 'ECDSA', hash: 'SHA-256'},
    kp.privateKey,
    new TextEncoder().encode(payload)
  );
  const verified = await subtle.verify(
    {name: 'ECDSA', hash: 'SHA-256'},
    kp.publicKey,
    sig,
    new TextEncoder().encode(payload)
  );
  return {
    extractable: kp.privateKey.extractable, // Luôn là false
    algorithm: 'ECDSA-P256-SHA256',
    publicJwk,
    payload,
    signatureBase64Url: Buffer.from(sig).toString('base64url'),
    verified
  };
}
