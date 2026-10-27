import {createWalletApp} from './wallet-app.js';

const port = Number(process.env.PORT) || 3000;
await createWalletApp({
  port,
  issuerPublicUrl: process.env.ISSUER_PUBLIC_URL || 'http://localhost:4001',
  verifierPublicUrl: process.env.VERIFIER_PUBLIC_URL || 'http://localhost:4002',
  issuerInternalUrl: process.env.ISSUER_INTERNAL_URL,
  verifierInternalUrl: process.env.VERIFIER_INTERNAL_URL
});
console.log(`[wallet-agent] http://localhost:${port}`);
