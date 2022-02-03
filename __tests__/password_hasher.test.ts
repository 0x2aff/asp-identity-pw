import {
  hashIdentityPasswordV2,
  hashIdentityPasswordV3,
  verifyPassword,
} from '../src/password_hasher';

const ASP_IDENTITY_PASSWORD_V2_BASE64 =
  'AFcg3t2gm81Guu+i08t6u4Hm00M1COvYfXvX8jwHMIBxS0sVsj6UHkk2qww8l4x/QA==';

const ASP_IDENTITY_PASSWORD_V2_HEX =
  '0058db9eba0db1297ddc7bf3c9070b110c58d21fb5bc85ad2bf8ef52e7b02f226acf051c105ee610e2e1bd6e6e74fc3d10';

const ASP_IDENTITY_PASSWORD_V3_BASE64 =
  'AQAAAAEAACcQAAAAEHheUovUgwiWJ7YO0aLoq2/TvJYEdPiBlNJplaMUaQKQPSu7SHMgf0zsEnhCVijJ0w==';

const ASP_IDENTITY_PASSWORD_V3_HEX =
  '01000000010000271000000010ebf7c556a2c8ca810d5ace7a909e228901e21b918d2ce94cd3f1f531f8690951cac9a34ad222fe8f77606a43300d60fa';

test('Hash Identity Password V2 (format: none)', () => {
  const password = '!passwordSecure123V2';
  const hash = hashIdentityPasswordV2(password);

  const result = verifyPassword(password, hash);
  expect(result).toBe(true);
});

test('Hash Identity Password V2 (format: base64)', () => {
  const password = '!passwordSecure123V2';
  const hash = hashIdentityPasswordV2(password, 'base64');

  const result = verifyPassword(password, hash, 'base64');
  expect(result).toBe(true);
});

test('Hash Identity Password V2 (format: hex)', () => {
  const password = '!passwordSecure123V2';
  const hash = hashIdentityPasswordV2(password, 'hex');

  const result = verifyPassword(password, hash, 'hex');
  expect(result).toBe(true);
});

test('Hash Identity Password V3 (format: none)', () => {
  const password = '!passwordSecure123V3';
  const hash = hashIdentityPasswordV3(password);

  const result = verifyPassword(password, hash);
  expect(result).toBe(true);
});

test('Hash Identity Password V3 (format: base64)', () => {
  const password = '!passwordSecure123V3';
  const hash = hashIdentityPasswordV3(password, 'base64');

  const result = verifyPassword(password, hash, 'base64');
  expect(result).toBe(true);
});

test('Hash Identity Password V3 (format: hex)', () => {
  const password = '!passwordSecure123V3';
  const hash = hashIdentityPasswordV3(password, 'hex');

  const result = verifyPassword(password, hash, 'hex');
  expect(result).toBe(true);
});

test('Verify Identity Password V2 (format: none)', () => {
  const result = verifyPassword(
    '!passwordSecure123ASPV2',
    ASP_IDENTITY_PASSWORD_V2_BASE64
  );

  expect(result).toBe(true);
});

test('Verify Identity Password V2 (format: base64)', () => {
  const result = verifyPassword(
    '!passwordSecure123ASPV2',
    ASP_IDENTITY_PASSWORD_V2_BASE64,
    'base64'
  );

  expect(result).toBe(true);
});

test('Verify Identity Password V2 (format: hex)', () => {
  const result = verifyPassword(
    '!passwordSecure123ASPV2',
    ASP_IDENTITY_PASSWORD_V2_HEX,
    'hex'
  );

  expect(result).toBe(true);
});

test('Verify Identity Password V2 (format: Buffer (base64))', () => {
  const hash = Buffer.from(ASP_IDENTITY_PASSWORD_V2_BASE64, 'base64');

  const result = verifyPassword('!passwordSecure123ASPV2', hash);

  expect(result).toBe(true);
});

test('Verify Identity Password V2 (format: Buffer (hex))', () => {
  const hash = Buffer.from(ASP_IDENTITY_PASSWORD_V2_HEX, 'hex');

  const result = verifyPassword('!passwordSecure123ASPV2', hash);

  expect(result).toBe(true);
});

test('Verify dentity Password V3 (format: none)', () => {
  const result = verifyPassword(
    '!passwordSecure123ASPV3',
    ASP_IDENTITY_PASSWORD_V3_BASE64
  );

  expect(result).toBe(true);
});

test('Verify dentity Password V3 (format: base64)', () => {
  const result = verifyPassword(
    '!passwordSecure123ASPV3',
    ASP_IDENTITY_PASSWORD_V3_BASE64,
    'base64'
  );

  expect(result).toBe(true);
});

test('Verify dentity Password V3 (format: hex)', () => {
  const result = verifyPassword(
    '!passwordSecure123ASPV3',
    ASP_IDENTITY_PASSWORD_V3_HEX,
    'hex'
  );

  expect(result).toBe(true);
});

test('Verify dentity Password V3 (format: Buffer(base64))', () => {
  const hash = Buffer.from(ASP_IDENTITY_PASSWORD_V3_BASE64, 'base64');

  const result = verifyPassword('!passwordSecure123ASPV3', hash);

  expect(result).toBe(true);
});

test('Verify dentity Password V3 (format: Buffer(hex))', () => {
  const hash = Buffer.from(ASP_IDENTITY_PASSWORD_V3_HEX, 'hex');

  const result = verifyPassword('!passwordSecure123ASPV3', hash);

  expect(result).toBe(true);
});
