const crypto = require('crypto');

function generateKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

function encryptRSA(publicKeyPem, buffer) {
  const pubKey = crypto.createPublicKey(publicKeyPem);
  return crypto.publicEncrypt(pubKey, buffer);
}

function decryptRSA(privateKey, buffer) {
  return crypto.privateDecrypt(privateKey, buffer);
}

function encryptAES(key, buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encrypted]);
}

function decryptAES(key, buffer) {
  const iv = buffer.slice(0, 12);
  const authTag = buffer.slice(12, 28);
  const ciphertext = buffer.slice(28);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function signMessage(privateKey, messageBuffer) {
  const sign = crypto.createSign('sha256');
  sign.update(messageBuffer);
  sign.end();
  return sign.sign(privateKey);
}

function verifySignature(publicKeyPem, messageBuffer, signatureBuffer) {
  const verify = crypto.createVerify('sha256');
  verify.update(messageBuffer);
  verify.end();
  const pubKey = crypto.createPublicKey(publicKeyPem);
  return verify.verify(pubKey, signatureBuffer);
}

module.exports = {
  generateKeys,
  encryptRSA,
  decryptRSA,
  encryptAES,
  decryptAES,
  signMessage,
  verifySignature,
};
