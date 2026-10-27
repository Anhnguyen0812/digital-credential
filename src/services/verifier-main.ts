import {createVerifierApp} from './verifier-app.js';

const port = Number(process.env.PORT) || 4002;
const mode = process.env.STATUS_CACHE_MODE === 'TTL_ONLY' ? 'TTL_ONLY' : 'ETAG_REVALIDATE';
const app = await createVerifierApp({
  port,
  publicUrl: process.env.VERIFIER_PUBLIC_URL || `http://localhost:${port}`,
  issuerPublicUrl: process.env.ISSUER_PUBLIC_URL || 'http://localhost:4001',
  issuerInternalUrl: process.env.ISSUER_INTERNAL_URL || process.env.ISSUER_PUBLIC_URL || 'http://localhost:4001',
  statusMode: mode,
  statusTtlSeconds: Number(process.env.STATUS_TTL_SECONDS) || 300
});
console.log(`[verifier-service] ${app.baseUrl}  trusted issuer=${app.issuerDid}  statusMode=${mode}`);
