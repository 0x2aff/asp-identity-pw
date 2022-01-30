/**
 * Specifies the PRF which should be used for the key derivation alogrithm.
 */
export enum KeyDerivationPrf {
  /** The HMAc algorithm (RFC 2104) using the SHA-1 hash function (FIPS 180-4). */
  HMAC_SHA1 = 0,
  /** The HMAC algorithm (RFC 2104) using the SHA-256 hash function (FIPS 180-4) */
  HMAC_SHA256 = 1,
}

/**
 * Returns the string representation of the specified key derivation prf.
 */
export const KdPrfDigestMap = {
  [KeyDerivationPrf.HMAC_SHA1]: 'sha1',
  [KeyDerivationPrf.HMAC_SHA256]: 'sha256',
};
