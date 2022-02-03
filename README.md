# ASP Identity Password Hasher

[![NPM version][npm-image]][npm-url]

## Info

### V2 Password

```
PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
Format: { 0x00, salt, subkey }
(See also: SDL crypto guidelines v5.1, Part III)
```

### V3 Password

```
PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.
Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
(All UInt32s are stored big-endian.)
```

---

## Example usage

### Password Hashing V2

#### Implicit as base64 encoded string

```javascript
import { hashIdentityPasswordV2 } from '../src/password_hasher';

// hashedPassword is stored as base64 encoded string.
const hashedPassword = hashIdentityPasswordV2('UltraSecurePassword1337');
```

#### Explicit as base64 encoded string

```javascript
import { hashIdentityPasswordV2 } from '../src/password_hasher';

// hashedPassword is explicitely stored as base64 encoded string.
const hashedPassword = hashIdentityPasswordV2(
  'UltraSecurePassword1337',
  'base64'
);
```

#### Explicit as hex encoded string

```javascript
import { hashIdentityPasswordV2 } from '../src/password_hasher';

// hashedPassword is explicitely stored as hex encoded string.
const hashedPassword = hashIdentityPasswordV2('UltraSecurePassword1337', 'hex');
```

### Password Hashing V3

#### Implicit as base64 encoded string

```javascript
import { hashIdentityPasswordV3 } from '../src/password_hasher';

// hashedPassword is stored as base64 encoded string.
const hashedPassword = hashIdentityPasswordV3('UltraSecurePassword1337');
```

#### Explicit as base64 encoded string

```javascript
import { hashIdentityPasswordV3 } from '../src/password_hasher';

// hashedPassword is explicitely stored as base64 encoded string.
const hashedPassword = hashIdentityPasswordV3(
  'UltraSecurePassword1337',
  'base64'
);
```

#### Explicit as hex encoded string

```javascript
import { hashIdentityPasswordV3 } from '../src/password_hasher';

// hashedPassword is explicitely stored as hex encoded string.
const hashedPassword = hashIdentityPasswordV3('UltraSecurePassword1337', 'hex');
```

---

### Verify Password

#### Implicit base64 encoded string

```javascript
import { verifyPassword } from '../src/password_hasher';

// Password from database as base64 encoded string.
const hashedPasswordFromDatabase = '...';

//  True if the password matches the hash, false otherwise.
const isValid = verifyPassword(
  'UltraSecurePassword1337',
  hashedPasswordFromDatabase
);
```

#### Explicit base64 encoded string

```javascript
import { verifyPassword } from '../src/password_hasher';

// Password from database as base64 encoded string.
const hashedPasswordFromDatabaseBase64 = '...';

//  True if the password matches the hash, false otherwise.
const isValid = verifyPassword(
  'UltraSecurePassword1337',
  hashedPasswordFromDatabase,
  'base64'
);
```

#### Explicit hex encoded string

```javascript
import { verifyPassword } from '../src/password_hasher';

// Password from database as base64 encoded string.
const hashedPasswordFromDatabaseHex = '...';

//  True if the password matches the hash, false otherwise.
const isValid = verifyPassword(
  'UltraSecurePassword1337',
  hashedPasswordFromDatabase,
  'hex'
);
```

#### Buffer from base64 encoded string

```javascript
import { verifyPassword } from '../src/password_hasher';

// Password from database as base64 encoded string.
const hashedPasswordFromDatabaseBase64 = '...';
const hashBuffer = Buffer.from(hashedPasswordFromDatabaseBase64, 'base64');

//  True if the password matches the hash, false otherwise.
const isValid = verifyPassword('UltraSecurePassword1337', hashBuffer);
```

#### Buffer from hex encoded string

```javascript
import { verifyPassword } from '../src/password_hasher';

// Password from database as base64 encoded string.
const hashedPasswordFromDatabaseHex = '...';
const hashBuffer = Buffer.from(hashedPasswordFromDatabaseHex, 'hex');

//  True if the password matches the hash, false otherwise.
const isValid = verifyPassword('UltraSecurePassword1337', hashBuffer);
```

[npm-url]: https://npmjs.org/package/asp-identity-pw
[npm-image]: https://img.shields.io/npm/v/asp-identity-pw.svg
