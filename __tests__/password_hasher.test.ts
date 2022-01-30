import {
  hashIdentityPasswordV2,
  hashIdentityPasswordV3,
  verifyPassword,
} from '../src/password_hasher';

const ASP_IDENTITY_PASSWORD_V2 =
  'AFcg3t2gm81Guu+i08t6u4Hm00M1COvYfXvX8jwHMIBxS0sVsj6UHkk2qww8l4x/QA==';

const ASP_IDENTITY_PASSWORD_V3 =
  'AQAAAAEAACcQAAAAEHheUovUgwiWJ7YO0aLoq2/TvJYEdPiBlNJplaMUaQKQPSu7SHMgf0zsEnhCVijJ0w==';

test('Hash Identity Password V2', () => {
  const password = '!passwordSecure123V2';
  const hash = hashIdentityPasswordV2(password);

  const result = verifyPassword(password, hash);
  expect(result).toBe(true);
});

test('Hash Identity Password V3', () => {
  const password = '!passwordSecure123V3';
  const hash = hashIdentityPasswordV3(password);

  const result = verifyPassword(password, hash);
  expect(result).toBe(true);
});

test('Verify Identity Password V2', () => {
  const result = verifyPassword(
    '!passwordSecure123ASPV2',
    ASP_IDENTITY_PASSWORD_V2
  );

  expect(result).toBe(true);
});

test('Verify dentity Password V3', () => {
  const result = verifyPassword(
    '!passwordSecure123ASPV3',
    ASP_IDENTITY_PASSWORD_V3
  );

  expect(result).toBe(true);
});
