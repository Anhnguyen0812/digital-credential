import * as vc from '@digitalbazaar/vc';
import {EDUCATION_CONTEXT_URL, EDUCATION_CONTEXT_DOC} from './education-v1.js';

export interface LoaderRegistry {
  didDocuments: Map<string, any>;
  verificationMethods: Map<string, any>;
}

export interface LoaderOptions {
  // did:web tu xa (vd. Verifier phan giai DID cua Issuer): did -> URL cua did.json.
  // Chi cac DID nam trong allowlist nay moi duoc phep truy van mang (chong SSRF).
  remoteDidDocuments?: Record<string, string>;
  fetchImpl?: typeof fetch;
}

const MULTIKEY_CONTEXT = 'https://w3id.org/security/multikey/v1';

export function createLoaderRegistry(): LoaderRegistry {
  return {didDocuments: new Map(), verificationMethods: new Map()};
}

// did:key:<multibase> cua khoa P-256 tu phan giai (khong can mang)
function resolveDidKey(url: string) {
  const m = /^(did:key:(z[1-9A-HJ-NP-Za-km-z]+))(#(.+))?$/.exec(url);
  if(!m) return null;
  const did = m[1];
  const mb = m[2];
  const vm = {'@context': MULTIKEY_CONTEXT, id: `${did}#${mb}`, type: 'Multikey', controller: did, publicKeyMultibase: mb};
  if(m[3]) return m[4] === mb ? vm : null;
  return {
    '@context': ['https://www.w3.org/ns/did/v1', MULTIKEY_CONTEXT],
    id: did,
    verificationMethod: [{id: vm.id, type: 'Multikey', controller: did, publicKeyMultibase: mb}],
    authentication: [vm.id],
    assertionMethod: [vm.id]
  };
}

export function createCustomDocumentLoader(registry: LoaderRegistry, options: LoaderOptions = {}) {
  const remoteCache = new Map<string, any>();

  return async function documentLoader(url: string): Promise<{contextUrl: null; documentUrl: string; document: any}> {
    if(url === EDUCATION_CONTEXT_URL) {
      return {contextUrl: null, documentUrl: url, document: structuredClone(EDUCATION_CONTEXT_DOC)};
    }
    if(registry.verificationMethods.has(url)) {
      return {contextUrl: null, documentUrl: url, document: structuredClone(registry.verificationMethods.get(url))};
    }
    const baseDid = url.split('#')[0];
    if(registry.didDocuments.has(baseDid)) {
      return {contextUrl: null, documentUrl: url, document: structuredClone(registry.didDocuments.get(baseDid))};
    }
    if(url.startsWith('did:key:')) {
      const doc = resolveDidKey(url);
      if(doc) return {contextUrl: null, documentUrl: url, document: doc};
    }
    const remote = options.remoteDidDocuments?.[baseDid];
    if(remote) {
      let didDoc = remoteCache.get(baseDid);
      if(!didDoc) {
        const res = await (options.fetchImpl ?? fetch)(remote);
        if(!res.ok) throw new Error(`[DID_RESOLVE] khong tai duoc ${baseDid}: HTTP ${res.status}`);
        didDoc = await res.json();
        remoteCache.set(baseDid, didDoc);
      }
      if(url === baseDid) return {contextUrl: null, documentUrl: url, document: structuredClone(didDoc)};
      const vm = (didDoc.verificationMethod || []).find((v: any) => v.id === url);
      if(vm) return {contextUrl: null, documentUrl: url, document: {'@context': MULTIKEY_CONTEXT, ...structuredClone(vm)}};
    }
    // Context chuan W3C (credentials v2, data-integrity v2, multikey v1, did v1) nap tinh tu goi @digitalbazaar/vc
    if(/^https:\/\/(www\.w3\.org|w3id\.org)\//.test(url)) {
      return (vc as any).defaultDocumentLoader(url);
    }
    throw new Error(`[SSRF_GUARD] Tu choi tai tai lieu khong nam trong allowlist: ${url}`);
  };
}
