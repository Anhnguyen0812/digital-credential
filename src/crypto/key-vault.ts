import {createCipheriv, createDecipheriv, randomBytes, scryptSync} from 'node:crypto';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';

/**
 * KeyVaultProvider — Bọc mã hóa khóa bí mật của Trường (Envelope Encryption AES-256-GCM).
 * Học tập từ kiến trúc bảo vệ khóa phát hành của Europass EDC / EBSI:
 * Khóa bí mật P-256 (secretKeyMultibase) KHÔNG BAO GIỜ lưu ở dạng rõ trong PostgreSQL.
 * Trước khi ghi xuống CSDL, khóa bí mật được mã hóa bằng khóa chủ (Master Key / KEK)
 * thông qua AES-256-GCM kèm thẻ xác thực authTag 16 bytes.
 */
export interface SealedKeyEnvelope {
  id: string;
  type: 'EncryptedMultikeyEnvelope';
  controller: string;
  publicKeyMultibase: string;
  cipher: 'aes-256-gcm';
  kdf: 'scrypt';
  keyId: string;
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
  sealedAt: string;
}

export interface SealedIssuerKeyBundle {
  vaultVersion: '1.0';
  issuerDid: string;
  issuer: SealedKeyEnvelope;
  approver: SealedKeyEnvelope;
}

function defaultMasterKey() {
  const configured = process.env.MASTER_KMS_KEY;
  if(configured) return configured;
  if(process.env.NODE_ENV === 'production') throw new Error('Thiếu MASTER_KMS_KEY');
  return process.env.SESSION_SECRET || 'vnu-kms-master-wrapping-key-2026';
}

function deriveKek(masterKey: string, salt: Buffer): Buffer {
  return scryptSync(masterKey, salt, 32, {N: 16384, r: 8, p: 1});
}

export function sealMultikey(
  exportedKeyPair: {
    id: string;
    controller: string;
    publicKeyMultibase: string;
    secretKeyMultibase?: string;
  },
  masterKey = defaultMasterKey(),
  keyId = 'kms-master-kek-v1'
): SealedKeyEnvelope {
  if (!exportedKeyPair.secretKeyMultibase) {
    throw new Error('KEY_VAULT_MISSING_SECRET: Không tìm thấy secretKeyMultibase để bọc mã hóa');
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const kek = deriveKek(masterKey, salt);
  const aad = Buffer.from(`${exportedKeyPair.id}|${exportedKeyPair.controller}|${exportedKeyPair.publicKeyMultibase}`, 'utf8');

  const cipher = createCipheriv('aes-256-gcm', kek, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(exportedKeyPair.secretKeyMultibase, 'utf8')),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();

  return {
    id: exportedKeyPair.id,
    type: 'EncryptedMultikeyEnvelope',
    controller: exportedKeyPair.controller,
    publicKeyMultibase: exportedKeyPair.publicKeyMultibase,
    cipher: 'aes-256-gcm',
    kdf: 'scrypt',
    keyId,
    salt: salt.toString('base64url'),
    iv: iv.toString('base64url'),
    authTag: authTag.toString('base64url'),
    ciphertext: encrypted.toString('base64url'),
    sealedAt: new Date().toISOString()
  };
}

export async function unsealMultikey(
  envelope: SealedKeyEnvelope,
  masterKey = defaultMasterKey()
): Promise<any> {
  if (!envelope || envelope.type !== 'EncryptedMultikeyEnvelope' || envelope.cipher !== 'aes-256-gcm') {
    throw new Error('KEY_VAULT_INVALID_ENVELOPE: Định dạng phong bì khóa không hợp lệ');
  }
  try {
    const salt = Buffer.from(envelope.salt, 'base64url');
    const iv = Buffer.from(envelope.iv, 'base64url');
    const authTag = Buffer.from(envelope.authTag, 'base64url');
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');
    const kek = deriveKek(masterKey, salt);
    const aad = Buffer.from(`${envelope.id}|${envelope.controller}|${envelope.publicKeyMultibase}`, 'utf8');

    const decipher = createDecipheriv('aes-256-gcm', kek, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const secretKeyMultibase = decrypted.toString('utf8');

    return await EcdsaMultikey.from({
      '@context': 'https://w3id.org/security/multikey/v1',
      type: 'Multikey',
      id: envelope.id,
      controller: envelope.controller,
      publicKeyMultibase: envelope.publicKeyMultibase,
      secretKeyMultibase
    });
  } catch {
    throw new Error('KEY_VAULT_DECRYPT_FAILED: Khóa chủ MASTER_KMS_KEY không khớp hoặc phong bì khóa đã bị can thiệp');
  }
}
