import {randomBytes, scryptSync, createCipheriv, createDecipheriv} from 'node:crypto';
import {createCustomDocumentLoader, createLoaderRegistry} from '../context/document-loader.js';
import {generateHolderKeyPair} from '../crypto/multikey-manager.js';
import {deriveVc, signPresentationWithHolder} from '../crypto/holder-binding.js';
import {DEGREE_SELECTIVE_MAP} from '../profiles/degree-profile.js';
import {COURSE_SELECTIVE_MAP} from '../profiles/course-profile.js';

// Ví người học (non-custodial): giữ khóa riêng của holder + Base VC. Derive và ký Holder Binding
// diễn ra hoàn toàn trong module này; Verifier/Issuer không bao giờ nhận Base VC.

export interface PreviewResult {
  verifier: string;
  credentialType: string;
  mandatory: string[];
  requestedOptional: string[];
  hidden: string[];
}

const MANDATORY_BY_TYPE: Record<string, string[]> = {
  DegreeCredential: ['studentName', 'graduated'],
  CourseCertificateCredential: ['studentName', 'courseName', 'certificateValid']
};

export type SimulateMode = 'normal' | 'attacker-key' | 'wrong-audience';

export class WalletClient {
  private constructor(
    private holderKeyPair: any,
    private readonly attackerKeyPair: any,
    private readonly documentLoader: any
  ) {}

  private store = new Map<string, any>();
  private history: {
    id: string;
    at: string;
    credentialId: string;
    verifier: string;
    disclosedClaims: string[];
    hiddenClaims: string[];
    deriveMs: number;
    signMs: number;
    status?: number;
  }[] = [];

  static async create() {
    const holder = await generateHolderKeyPair();
    const attacker = await generateHolderKeyPair();
    return new WalletClient(holder, attacker, createCustomDocumentLoader(createLoaderRegistry()));
  }

  get did(): string { return this.holderKeyPair.controller; }

  async signOpenId4VciProof(cNonce: string, issuerDid: string): Promise<string> {
    const bytes = new TextEncoder().encode(`openid4vci-proof|${cNonce}|${issuerDid}`);
    const sig: Uint8Array = await this.holderKeyPair.signer().sign({data: bytes});
    return Buffer.from(sig).toString('base64url');
  }

  async exportBackup(passphrase?: string) {
    const exportedKey = await this.holderKeyPair.export({publicKey: true, secretKey: true});
    const credentials = [...this.store.entries()].map(([id, vc]) => ({id, credential: vc}));
    const plain = {
      version: 'vnu-wallet-backup-v1',
      exportedAt: new Date().toISOString(),
      did: this.did,
      keyPair: exportedKey,
      credentials
    };
    if (!passphrase) return plain;
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = scryptSync(passphrase, salt, 32);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(plain), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      version: 'vnu-wallet-encrypted-v1',
      kdf: 'scrypt',
      cipher: 'aes-256-gcm',
      exportedAt: plain.exportedAt,
      didHint: this.did.slice(0, 28) + '…',
      credentialCount: credentials.length,
      salt: salt.toString('base64url'),
      iv: iv.toString('base64url'),
      tag: tag.toString('base64url'),
      ciphertext: ciphertext.toString('base64url')
    };
  }

  async restoreBackup(bundle: any, passphrase?: string) {
    let target = bundle;
    if (bundle?.version === 'vnu-wallet-encrypted-v1' || bundle?.ciphertext) {
      if (!passphrase) throw new Error('Cần nhập mật khẩu giải mã bản sao lưu (AES-256-GCM)');
      try {
        const salt = Buffer.from(bundle.salt, 'base64url');
        const iv = Buffer.from(bundle.iv, 'base64url');
        const tag = Buffer.from(bundle.tag, 'base64url');
        const ct = Buffer.from(bundle.ciphertext, 'base64url');
        const key = scryptSync(passphrase, salt, 32);
        const decipher = createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const json = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
        target = JSON.parse(json);
      } catch {
        throw new Error('Mật khẩu giải mã bản sao lưu không đúng hoặc tệp bị hỏng');
      }
    }
    if (!target?.keyPair || !Array.isArray(target?.credentials)) {
      throw new Error('Gói sao lưu Ví không hợp lệ');
    }
    const {fromHolderMultikey} = await import('../crypto/multikey-manager.js');
    this.holderKeyPair = await fromHolderMultikey(target.keyPair);
    this.store.clear();
    for (const item of target.credentials) {
      if (item?.id && item?.credential) {
        this.store.set(item.id, item.credential);
      }
    }
    return {did: this.did, count: this.store.size};
  }

  async rotateNewDevice() {
    const previousDid = this.did;
    this.holderKeyPair = await generateHolderKeyPair();
    this.store.clear();
    return {previousDid, newDid: this.did};
  }

  addCredential(id: string, baseVc: any) { this.store.set(id, baseVc); }
  removeCredential(id: string) { this.store.delete(id); }
  listCredentials() {
    return [...this.store.entries()].map(([id, vc]) => ({
      id,
      type: vc.type,
      hasLegacy: !!vc.credentialSubject?.legacyProvenance,
      statusListIndex: vc.credentialStatus?.statusListIndex,
      validFrom: vc.validFrom,
      validUntil: vc.validUntil,
      subject: vc.credentialSubject
    }));
  }
  getHistory() { return this.history; }
  recordHistory(entry: Omit<WalletClient['history'][number], 'id' | 'at'>) {
    this.history.unshift({
      id: randomBytes(6).toString('hex'),
      at: new Date().toISOString(),
      ...entry
    });
  }
  getBaseCredential(id: string) { return this.store.get(id); } // chi dung cho tab "Du lieu goc trong Vi"

  private typeOf(vc: any): string {
    return (vc.type as string[]).find(t => t !== 'VerifiableCredential' && t !== 'LegacyReissuedCredential') as string;
  }

  private selectiveMap(vc: any) {
    return this.typeOf(vc) === 'CourseCertificateCredential' ? COURSE_SELECTIVE_MAP : DEGREE_SELECTIVE_MAP;
  }

  preview(request: any, credentialId: string): PreviewResult {
    const vc = this.store.get(credentialId);
    if(!vc) throw new Error('khong co chung chi nay trong vi');
    const type = this.typeOf(vc);
    const subjectKeys = Object.keys(vc.credentialSubject).filter(k => k !== 'id');
    const mandatory = subjectKeys.filter(k => MANDATORY_BY_TYPE[type].includes(k) || k === 'legacyProvenance');
    const requested = (request?.dcql_query?.credentials?.[0]?.claims || []).map((c: any) => c.path[c.path.length - 1]);
    const requestedOptional = requested.filter((k: string) => subjectKeys.includes(k) && !mandatory.includes(k));
    const hidden = subjectKeys.filter(k => !mandatory.includes(k) && !requestedOptional.includes(k));
    return {verifier: request?.client_id, credentialType: type, mandatory, requestedOptional, hidden};
  }

  async present(params: {
    request: any;
    credentialId: string;
    approvedClaims?: string[];
    consent: boolean;
    simulate?: SimulateMode;
  }) {
    if(params.consent !== true) throw new Error('NO_CONSENT');
    const vc = this.store.get(params.credentialId);
    if(!vc) throw new Error('khong co chung chi nay trong vi');
    const map = this.selectiveMap(vc);
    const preview = this.preview(params.request, params.credentialId);
    const approved = (params.approvedClaims ?? preview.requestedOptional).filter(c => preview.requestedOptional.includes(c));
    const pointers = approved.map(c => map[c]).filter(Boolean);

    const t0 = performance.now();
    const derivedVc = await deriveVc({baseCredential: vc, selectivePointers: pointers, documentLoader: this.documentLoader});
    const deriveMs = performance.now() - t0;

    const simulate = params.simulate ?? 'normal';
    const keyPair = simulate === 'attacker-key' ? this.attackerKeyPair : this.holderKeyPair;
    const audience = simulate === 'wrong-audience' ? 'redirect_uri:https://verifier-B.evil.example/direct-post' : params.request.client_id;

    const t1 = performance.now();
    const vp = await signPresentationWithHolder({derivedVc, holderKeyPair: keyPair, nonce: params.request.nonce, audience, documentLoader: this.documentLoader});
    const signMs = performance.now() - t1;

    return {
      vp_token: {[params.request.dcql_query.credentials[0].id]: [vp]} as Record<string, any[]>,
      state: params.request.state,
      deriveMs, signMs,
      disclosedClaims: approved
    };
  }
}
