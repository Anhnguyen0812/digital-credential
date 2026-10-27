import {gzipSync, gunzipSync} from 'node:zlib';

// W3C Bitstring Status List v1.0
// - Do dai toi thieu 131.072 bit (16 KB) de dam bao herd privacy
// - Nen bang GZIP (RFC 1952), sau do multibase base64url khong padding (tien to 'u')
// - Index 0 nam o bit trai nhat (most significant bit) cua byte dau tien
export const MIN_LIST_LENGTH = 131_072;
export const MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024; // chong zip bomb: toi da 2 MB

export class BitstringStatusList {
  readonly length: number;
  private bytes: Uint8Array;

  constructor(length = MIN_LIST_LENGTH, bytes?: Uint8Array) {
    if(length < MIN_LIST_LENGTH) {
      throw new Error(`status list phai co it nhat ${MIN_LIST_LENGTH} bit`);
    }
    this.length = length;
    this.bytes = bytes ?? new Uint8Array(Math.ceil(length / 8));
  }

  private assertIndex(index: number) {
    if(!Number.isInteger(index) || index < 0 || index >= this.length) {
      throw new RangeError('statusListIndex nam ngoai pham vi danh sach');
    }
  }

  set(index: number, value: boolean) {
    this.assertIndex(index);
    const byteIndex = Math.floor(index / 8);
    const mask = 1 << (7 - (index % 8));
    if(value) this.bytes[byteIndex] |= mask;
    else this.bytes[byteIndex] &= ~mask;
  }

  get(index: number): boolean {
    this.assertIndex(index);
    const byteIndex = Math.floor(index / 8);
    return ((this.bytes[byteIndex] >> (7 - (index % 8))) & 1) === 1;
  }

  encode(): string {
    const gz = gzipSync(this.bytes);
    return 'u' + Buffer.from(gz).toString('base64url');
  }

  static decode(encodedList: string): BitstringStatusList {
    if(typeof encodedList !== 'string' || !encodedList.startsWith('u')) {
      throw new Error('encodedList phai la multibase base64url (tien to u)');
    }
    const gz = Buffer.from(encodedList.slice(1), 'base64url');
    const raw = gunzipSync(gz, {maxOutputLength: MAX_DECOMPRESSED_BYTES});
    const length = raw.length * 8;
    if(length < MIN_LIST_LENGTH) {
      throw new Error('STATUS_LIST_LENGTH_ERROR: danh sach ngan hon 131.072 bit');
    }
    return new BitstringStatusList(length, new Uint8Array(raw));
  }
}

// Tao Status List Credential (chua ky) theo mau cua dac ta
export function makeStatusListCredential(listUrl: string, issuer: string, list: BitstringStatusList) {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: listUrl,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer,
    validFrom: '2026-08-01T00:00:00Z',
    credentialSubject: {
      id: listUrl + '#list',
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList: list.encode()
    }
  };
}
