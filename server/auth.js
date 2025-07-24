const crypto = require('crypto');

const HASH_ALGO = 'sha256';
const SALT_BYTES = 16;
const HASH_ITERATIONS = 100000;
const KEY_LEN = 64;

function hashPassword(password, salt = null) {
  salt = salt || crypto.randomBytes(SALT_BYTES).toString('hex');
  const hashed = crypto.pbkdf2Sync(password, salt, HASH_ITERATIONS, KEY_LEN, HASH_ALGO).toString('hex');
  return { salt, hashedPassword: hashed };
}

function verifyPassword(password, salt, hashedPassword) {
  const { hashedPassword: hashToVerify } = hashPassword(password, salt);
  return hashToVerify === hashedPassword;
}

function isValidPassword(password) {
  return typeof password === 'string'
    && password.length >= 8
    && /\d/.test(password);
}

module.exports = {
  hashPassword,
  verifyPassword,
  isValidPassword
};
