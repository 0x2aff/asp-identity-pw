import * as crypto from 'crypto';
import { KdPrfDigestMap, KeyDerivationPrf } from './key_derivation_prf';

/**
 * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
 * Format: { 0x00, salt, subkey }
 * (See also: SDL crypto guidelines v5.1, Part III)
 * @param password Hashed password as base64 encoded string
 */
export const hashIdentityPasswordV2 = (
  password: string,
  outputFormat: 'base64' | 'hex' = 'base64'
): string => {
  const options = {
    salt: crypto.randomBytes(128 / 8),
    prf: KeyDerivationPrf.HMAC_SHA1,
    iter: 1000,
    keylen: 256 / 8,
  };

  return hashPassword(
    password,
    options.salt,
    options.prf,
    options.iter,
    options.keylen,
    outputFormat
  );
};

/**
 * PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.
 * Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
 * (All UInt32s are stored big-endian.)
 * @param password The password that should be hashed.
 * @returns Hashed password as base64 encoded string
 */
export const hashIdentityPasswordV3 = (
  password: string,
  outputFormat: 'base64' | 'hex' = 'base64'
): string => {
  const options = {
    salt: crypto.randomBytes(128 / 8),
    prf: KeyDerivationPrf.HMAC_SHA256,
    iter: 10000,
    keylen: 256 / 8,
  };

  return hashPassword(
    password,
    options.salt,
    options.prf,
    options.iter,
    options.keylen,
    outputFormat
  );
};

/**
 * Verifies a password that was hashed using the @see hashPassword function.
 * @param password The password to verify.
 * @param hash The hash to verify the password against (in base64 encoding).
 * @returns True if the password matches the hash, false otherwise.
 */
export const verifyPassword = (
  password: string,
  hash: Buffer | string,
  inputFormat: 'base64' | 'hex' = 'base64'
): boolean => {
  const hashBuffer = Buffer.isBuffer(hash)
    ? hash
    : Buffer.from(hash, inputFormat);

  const usedPrf = getPrfMethodFromHash(hashBuffer);
  const digestString = KdPrfDigestMap[usedPrf];

  switch (usedPrf) {
    case KeyDerivationPrf.HMAC_SHA1: {
      const iterationCount = 1000;
      const saltLength = 128 / 8;

      const salt = Buffer.alloc(saltLength);
      hashBuffer.copy(salt, 0, 1, 1 + saltLength);

      const derivedKeyLength = hashBuffer.length - 1 - saltLength;
      const derivedKey = Buffer.alloc(derivedKeyLength);
      hashBuffer.copy(
        derivedKey,
        0,
        1 + saltLength,
        1 + saltLength + derivedKeyLength
      );

      const result = crypto.pbkdf2Sync(
        password,
        salt,
        iterationCount,
        derivedKeyLength,
        digestString
      );

      return result.equals(derivedKey);
    }
    case KeyDerivationPrf.HMAC_SHA256: {
      const iterationCount = readNetworkByteOrder(hashBuffer, 5);
      const saltLength = readNetworkByteOrder(hashBuffer, 9);

      const salt = Buffer.alloc(saltLength);
      hashBuffer.copy(salt, 0, 13, 13 + saltLength);

      const derivedKeyLength = hashBuffer.length - 13 - saltLength;
      const derivedKey = Buffer.alloc(derivedKeyLength);
      hashBuffer.copy(
        derivedKey,
        0,
        13 + saltLength,
        13 + saltLength + derivedKeyLength
      );

      const result = crypto.pbkdf2Sync(
        password,
        salt,
        iterationCount,
        derivedKeyLength,
        digestString
      );

      return result.equals(derivedKey);
    }
    default:
      throw new Error(`Unknown key derivation prf: ${usedPrf}`);
  }
};

const hashPassword = (
  password: string,
  salt: string | Buffer,
  prf: KeyDerivationPrf,
  iterations: number,
  keyLength: number,
  outputFormat: 'base64' | 'hex' = 'base64'
): string => {
  const digestString = KdPrfDigestMap[prf];
  const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'binary');

  if (!digestString) throw new Error(`Unknown key derivation prf: ${prf}`);

  const derivedKey = crypto.pbkdf2Sync(
    password,
    saltBuffer,
    iterations,
    keyLength,
    digestString
  );

  switch (prf) {
    case KeyDerivationPrf.HMAC_SHA1: {
      const outputBytes = Buffer.alloc(
        1 + saltBuffer.length + derivedKey.length
      );
      outputBytes[0] = PrfBitMap[prf];

      saltBuffer.copy(outputBytes, 1);
      derivedKey.copy(outputBytes, 1 + saltBuffer.length);

      return outputBytes.toString(outputFormat);
    }
    case KeyDerivationPrf.HMAC_SHA256: {
      const outputBytes = Buffer.alloc(13 + salt.length + derivedKey.length);
      outputBytes[0] = PrfBitMap[prf];

      writeNetworkByteOrder(outputBytes, 1, 1);
      writeNetworkByteOrder(outputBytes, 5, iterations);
      writeNetworkByteOrder(outputBytes, 9, salt.length);

      saltBuffer.copy(outputBytes, 13);
      derivedKey.copy(outputBytes, 13 + salt.length);

      return outputBytes.toString(outputFormat);
    }
    default:
      throw new Error(`Unknown key derivation prf: ${prf}`);
  }
};

const getPrfMethodFromHash = (hash: Buffer): KeyDerivationPrf => {
  return BitPrfMap[hash[0]];
};

const PrfBitMap: { [key: number]: number } = {
  [KeyDerivationPrf.HMAC_SHA1]: 0x00,
  [KeyDerivationPrf.HMAC_SHA256]: 0x01,
};

const BitPrfMap: { [key: number]: number } = {
  [0x00]: KeyDerivationPrf.HMAC_SHA1,
  [0x01]: KeyDerivationPrf.HMAC_SHA256,
};

const readNetworkByteOrder = (buffer: Buffer, offset: number): number => {
  return (
    (buffer[offset + 0] << 24) |
    (buffer[offset + 1] << 16) |
    (buffer[offset + 2] << 8) |
    buffer[offset + 3]
  );
};

const writeNetworkByteOrder = (
  buffer: Buffer,
  offset: number,
  value: number
) => {
  // Magic numbers beste numbers
  buffer[offset + 0] = (value >> 24) & 0xff;
  buffer[offset + 1] = (value >> 16) & 0xff;
  buffer[offset + 2] = (value >> 8) & 0xff;
  buffer[offset + 3] = (value >> 0) & 0xff;
};
