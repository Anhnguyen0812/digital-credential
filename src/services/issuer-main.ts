import {createIssuerApp} from './issuer-app.js';

const port = Number(process.env.PORT) || 4001;
const app = await createIssuerApp({
  port,
  publicUrl: process.env.ISSUER_PUBLIC_URL || `http://localhost:${port}`
});
console.log(`[issuer-service] ${app.baseUrl}  did=${app.issuerDid}  db=${app.store.mode}`);
