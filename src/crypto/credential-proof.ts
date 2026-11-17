import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';

function encode(data: object) {
  return Buffer.from(JSON.stringify(data)).toString('base64url');
}

export async function signCredentialProof(key: any, nonce: string, audience: string) {
  const header = encode({typ: 'openid4vci-proof+jwt', alg: 'ES256', kid: key.id});
  const payload = encode({aud: audience, nonce, iat: Math.floor(Date.now() / 1000)});
  const input = header + '.' + payload;
  const signature = await key.signer().sign({data: Buffer.from(input)});
  return input + '.' + Buffer.from(signature).toString('base64url');
}

export async function verifyCredentialProof(proof: unknown, holderDid: string, nonce: string, audience: string) {
  if(typeof proof !== 'string' || proof.length > 4096) return false;
  const parts = proof.split('.');
  if(parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) return false;
  try {
    const [protectedHeader, claims, signature] = parts;
    const header = JSON.parse(Buffer.from(protectedHeader, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(claims, 'base64url').toString('utf8'));
    const publicKeyMultibase = holderDid.slice('did:key:'.length);
    const id = holderDid + '#' + publicKeyMultibase;
    const now = Math.floor(Date.now() / 1000);
    if(header.typ !== 'openid4vci-proof+jwt' || header.alg !== 'ES256' || header.kid !== id || header.jwk || header.x5c || header.crit ||
      payload.aud !== audience || payload.nonce !== nonce || !Number.isSafeInteger(payload.iat) ||
      payload.iat > now + 5 || payload.iat < now - 120) return false;
    const key = await EcdsaMultikey.from({
      '@context': 'https://w3id.org/security/multikey/v1', type: 'Multikey', id,
      controller: holderDid, publicKeyMultibase
    });
    const jwk = await EcdsaMultikey.toJwk({keyPair: key});
    const bytes = Buffer.from(signature, 'base64url');
    if(jwk.crv !== 'P-256' || bytes.length !== 64) return false;
    return await key.verifier().verify({data: Buffer.from(protectedHeader + '.' + claims), signature: bytes});
  } catch {
    return false;
  }
}
