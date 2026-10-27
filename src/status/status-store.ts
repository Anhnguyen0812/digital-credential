import {BitstringStatusList, MIN_LIST_LENGTH} from './bitstring-status.js';

// Tuan 7: StatusStore duoc thay ruot bang W3C Bitstring Status List (131.072 bit)
// thay vi Set<number> trong RAM nhu tuan 4. API giu nguyen de test cu van chay.
export class StatusStore {
  readonly list: BitstringStatusList;

  constructor(list?: BitstringStatusList) {
    this.list = list ?? new BitstringStatusList(MIN_LIST_LENGTH);
  }

  static fromEncodedList(encodedList: string) {
    return new StatusStore(BitstringStatusList.decode(encodedList));
  }

  revoke(no: number) {
    this.list.set(no, true);
  }

  restore(no: number) {
    this.list.set(no, false);
  }

  isRevoked(no: number) {
    return this.list.get(no);
  }

  check(credential: any) {
    const item = credential?.credentialStatus;
    if(!item) return {verified: true};
    if(item.type !== 'BitstringStatusListEntry' || item.statusPurpose !== 'revocation') {
      return {verified: false, reason: 'credentialStatus khong dung chuan BitstringStatusListEntry'};
    }
    const no = Number(item.statusListIndex);
    if(!Number.isInteger(no) || no < 0 || no >= this.list.length) {
      return {verified: false, reason: 'status index khong hop le'};
    }
    if(this.isRevoked(no)) {
      return {verified: false, reason: 'credential da bi thu hoi'};
    }
    return {verified: true};
  }
}

// =====================================================================
// Tuan 8 (FIX-04): IssuerStatusRegistry + VerifierStatusCache (ETag / TTL)
// =====================================================================
import {createHash} from 'node:crypto';
import * as vc from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as rdfcCryptosuite} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';

export class IssuerStatusRegistry {
  readonly list = new BitstringStatusList(MIN_LIST_LENGTH);
  private currentCredential: any = null;
  private currentETag = '';
  private nextIndex = 1;

  constructor(
    readonly listUrl: string,
    private readonly issuerKeyPair: any,
    private readonly documentLoader: any
  ) {}

  allocateIndex(): number {
    return this.nextIndex++;
  }

  async publishSignedStatusList(): Promise<{credential: any; etag: string}> {
    const encodedList = this.list.encode();
    this.currentETag = `W/"${createHash('sha256').update(encodedList).digest('hex').slice(0, 32)}"`;
    const unsigned = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: this.listUrl,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: this.issuerKeyPair.controller,
      validFrom: new Date().toISOString(),
      credentialSubject: {
        id: `${this.listUrl}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList
      }
    };
    const suite = new DataIntegrityProof({
      signer: this.issuerKeyPair.signer(),
      cryptosuite: rdfcCryptosuite
    });
    this.currentCredential = await vc.issue({credential: unsigned, suite, documentLoader: this.documentLoader});
    return {credential: this.currentCredential, etag: this.currentETag};
  }

  async setRevoked(index: number, revoked = true) {
    this.list.set(index, revoked);
    return this.publishSignedStatusList();
  }

  isRevoked(index: number) {
    return this.list.get(index);
  }

  get allocatedCount() { return this.nextIndex - 1; }
  get etag() { return this.currentETag; }

  // Khoi phuc trang thai sau khi khoi dong lai (doc tu CSDL): chi so tiep theo + cac bit da thu hoi
  async restore(nextIndex: number, revokedIndexes: number[]) {
    this.nextIndex = Math.max(this.nextIndex, nextIndex);
    for(const i of revokedIndexes) this.list.set(i, true);
    return this.publishSignedStatusList();
  }

  // Mo phong HTTP GET: If-None-Match khop ETag hien tai -> 304 (khong body)
  async handleHttpGet(ifNoneMatch?: string): Promise<{status: 200 | 304; etag: string; body?: any}> {
    if(!this.currentCredential) await this.publishSignedStatusList();
    if(ifNoneMatch && ifNoneMatch === this.currentETag) return {status: 304, etag: this.currentETag};
    return {status: 200, etag: this.currentETag, body: this.currentCredential};
  }
}

export type StatusCacheMode = 'TTL_ONLY' | 'ETAG_REVALIDATE';
export type StatusFetcher = (ifNoneMatch?: string) => Promise<{status: number; etag?: string; body?: any}>;

// Verifier-side cache: danh doi rieng tu (cache hit, khong goi truong) vs do tuoi thu hoi (ETag revalidate).
export class VerifierStatusCache {
  private cached: {list: BitstringStatusList; etag: string; fetchedAt: number} | null = null;
  readonly counters = {cacheHits: 0, revalidate304: 0, fullFetch200: 0};

  constructor(
    private readonly fetcher: StatusFetcher,
    private readonly documentLoader: any,
    private readonly opts: {mode: StatusCacheMode; ttlMs: number} = {mode: 'ETAG_REVALIDATE', ttlMs: 300_000}
  ) {}

  setMode(mode: StatusCacheMode) { this.opts.mode = mode; }
  setTtl(ttlMs: number) { this.opts.ttlMs = ttlMs; }
  getMode() { return this.opts.mode; }
  invalidate() { this.cached = null; }

  async getList(): Promise<BitstringStatusList> {
    const now = Date.now();
    const fresh = this.cached && now - this.cached.fetchedAt < this.opts.ttlMs;
    if(this.cached && fresh && this.opts.mode === 'TTL_ONLY') {
      this.counters.cacheHits++;
      return this.cached.list;
    }
    const res = await this.fetcher(this.cached?.etag);
    if(res.status === 304 && this.cached) {
      this.cached.fetchedAt = now;
      this.counters.revalidate304++;
      return this.cached.list;
    }
    const slc = res.body;
    const result = await vc.verifyCredential({
      credential: slc,
      suite: new DataIntegrityProof({cryptosuite: rdfcCryptosuite}),
      documentLoader: this.documentLoader,
      checkStatus: async () => ({verified: true})
    });
    if(!result.verified) throw new Error('chu ky Status List Credential khong hop le');
    const list = BitstringStatusList.decode(slc.credentialSubject.encodedList);
    this.cached = {list, etag: res.etag || '', fetchedAt: now};
    this.counters.fullFetch200++;
    return list;
  }

  async check(credential: any): Promise<{verified: boolean; reason?: string}> {
    const item = credential?.credentialStatus;
    if(!item) return {verified: true};
    if(item.type !== 'BitstringStatusListEntry' || item.statusPurpose !== 'revocation') {
      return {verified: false, reason: 'credentialStatus khong dung chuan BitstringStatusListEntry'};
    }
    const idx = Number(item.statusListIndex);
    const list = await this.getList();
    if(!Number.isInteger(idx) || idx < 0 || idx >= list.length) return {verified: false, reason: 'status index khong hop le'};
    if(list.get(idx)) return {verified: false, reason: 'credential da bi thu hoi'};
    return {verified: true};
  }
}

