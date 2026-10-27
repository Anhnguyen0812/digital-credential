import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {LoaderRegistry, createLoaderRegistry} from '../context/document-loader.js';

export interface SystemIdentities {
  issuerKeyPair: any;
  approverKeyPair: any;
  holderKeyPair: any;
  attackerKeyPair: any; // dung cho ca kiem thu tan cong Holder Binding (W4.x)
  registry: LoaderRegistry;
}

export const DEFAULT_ISSUER_DID = 'did:web:university.edu.vn';

// Sinh khoa P-256 Multikey cho 1 holder, controller = did:key
export async function generateHolderKeyPair(extractable = true) {
  const temp = await EcdsaMultikey.generate({curve: 'P-256'});
  const controller = `did:key:${temp.publicKeyMultibase}`;
  const exported = await temp.export({publicKey: true, secretKey: true});
  void extractable;
  return EcdsaMultikey.from({...exported, controller, id: `${controller}#${temp.publicKeyMultibase}`});
}

export async function fromHolderMultikey(exported: any) {
  return EcdsaMultikey.from(exported);
}

export async function registerKey(registry: LoaderRegistry, kp: any) {
  const pubDoc = await kp.export({publicKey: true, includeContext: true});
  registry.verificationMethods.set(kp.id, pubDoc);
  const did = registry.didDocuments.get(kp.controller) || {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: kp.controller,
    verificationMethod: [],
    assertionMethod: [],
    authentication: []
  };
  did.verificationMethod.push(pubDoc);
  did.assertionMethod.push(kp.id);
  did.authentication.push(kp.id);
  registry.didDocuments.set(kp.controller, did);
}

export async function generateIssuerKeys(issuerDid = DEFAULT_ISSUER_DID) {
  const issuerKeyPair = await EcdsaMultikey.generate({curve: 'P-256', controller: issuerDid, id: `${issuerDid}#issuer-key-1`});
  const approverKeyPair = await EcdsaMultikey.generate({curve: 'P-256', controller: issuerDid, id: `${issuerDid}#approver-key-1`});
  return {issuerKeyPair, approverKeyPair};
}

export async function initializeIdentities(issuerDid = DEFAULT_ISSUER_DID): Promise<SystemIdentities> {
  const registry = createLoaderRegistry();
  const {issuerKeyPair, approverKeyPair} = await generateIssuerKeys(issuerDid);
  const holderKeyPair = await generateHolderKeyPair();
  const attackerKeyPair = await generateHolderKeyPair();
  for(const kp of [issuerKeyPair, approverKeyPair, holderKeyPair, attackerKeyPair]) await registerKey(registry, kp);
  return {issuerKeyPair, approverKeyPair, holderKeyPair, attackerKeyPair, registry};
}
