const bcrypt = require('bcryptjs');

const BCRYPT_COST = 12;
const MAX_PASSWORD_BYTES = 72;
// No normalization: an account's password is the exact UTF-8 string entered.
const isAcceptablePasswordInput = (value) =>
  typeof value === 'string' && value.length > 0 &&
  Buffer.byteLength(value, 'utf8') <= MAX_PASSWORD_BYTES && !value.includes('\0');

const hashPassword = async (value) => {
  if (!isAcceptablePasswordInput(value)) throw new Error('Invalid password input.');
  return bcrypt.hash(value, BCRYPT_COST);
};

// Comparable work on unknown-account and known-account failures.
const dummyHash = bcrypt.hashSync('Unusable dummy authentication password', BCRYPT_COST);
const comparePassword = async (value, hash) => {
  const valid = isAcceptablePasswordInput(value);
  const result = await bcrypt.compare(valid ? value : 'invalid', hash || dummyHash);
  return valid && Boolean(hash) && result;
};

module.exports = { BCRYPT_COST, comparePassword, hashPassword, isAcceptablePasswordInput };
