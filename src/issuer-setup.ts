import * as vc from '@digitalbazaar/vc';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {DEGREE_CONTEXT, degreeContextDocument, ISSUER_ID, KEY_ID} from './config.js';

export async function makeIssuerSetup() {
  const keyPair = await EcdsaMultikey.generate({
    curve: 'P-256',
    id: KEY_ID,
    controller: ISSUER_ID
  });

  const publicKey = await keyPair.export({publicKey: true, includeContext: true});
  const controller = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1'
    ],
    id: ISSUER_ID,
    verificationMethod: [publicKey],
    assertionMethod: [KEY_ID]
  };

  const localDocs = new Map<string, any>();
  localDocs.set(DEGREE_CONTEXT, degreeContextDocument);
  localDocs.set(KEY_ID, publicKey);
  localDocs.set(ISSUER_ID, controller);

  const documentLoader = async (url: string) => {
    const item = localDocs.get(url);
    if(item) {
      return {contextUrl: null, documentUrl: url, document: item};
    }
    return vc.defaultDocumentLoader(url);
  };

  return {keyPair, publicKey, controller, documentLoader};
}
