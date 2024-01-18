/**
 * 
 * Package: 
 * Author: Ganesh B
 * Description: 
 * Install: npm i  --save
 * Github: https://github.com/ganeshkbhat/
 * npmjs Link: https://www.npmjs.com/package/
 * File: index.js
 * File Description: 
 * 
*/

/* eslint no-console: 0 */

'use strict';

import crypto from "node:crypto";

// function decrypt_string(encryptedMessage, encryptionMethod, secret, iv) {
//   const buff = Buffer.from(encryptedMessage, 'base64');
//   encryptedMessage = buff.toString('utf-8');
//   var decryptor = Crypto.createDecipheriv(encryptionMethod, secret, iv);
//   return decryptor.update(encryptedMessage, 'base64', 'utf8') + decryptor.final('utf8');
// };

// function decrypt_string(encryptedMessage, encryptionMethod, secret, iv) {
//   const buff = Buffer.from(encryptedMessage, 'base64');
//   encryptedMessage = buff.toString('utf-8');
//   var decryptor = Crypto.createDecipheriv(encryptionMethod, secret, iv);
//   return decryptor.update(encryptedMessage, 'base64', 'utf8') + decryptor.final('utf8');
// };

/** @type { BLOCK_CIPHER, AUTH_TAG_BYTE_LEN, IV_BYTE_LEN, KEY_BYTE_LEN, SALT_BYTE_LEN } */
const ALGORITHM = {

  /**
   * GCM is an authenticated encryption mode that
   * not only provides confidentiality but also 
   * provides integrity in a secured way
   * */
  BLOCK_CIPHER: 'aes-256-gcm',

  /**
   * 128 bit auth tag is recommended for GCM
   */
  AUTH_TAG_BYTE_LEN: 16,

  /**
   * NIST recommends 96 bits or 12 bytes IV for GCM
   * to promote interoperability, efficiency, and
   * simplicity of design
   */
  IV_BYTE_LEN: 12,

  /**
   * Note: 256 (in algorithm name) is key size. 
   * Block size for AES is always 128
   */
  KEY_BYTE_LEN: 32,

  /**
   * To prevent rainbow table attacks
   * */
  SALT_BYTE_LEN: 16
}

/**
 *
 * getIV
 * 
 * Function to get a IV value using a standard IV byte length
 *
 */
const getIV = () => crypto.randomBytes(ALGORITHM.IV_BYTE_LEN);

/**
 * getRandomKey
 * 
 * Function to get a Key for a Crypto.CipherIV key
 *
 */
const getRandomKey = () => crypto.randomBytes(ALGORITHM.KEY_BYTE_LEN);

/**
 * 
 * getSalt
 * 
 * Function to get a salt of specific byte length 
 * 
 * To prevent rainbow table attacks
 */
const getSalt = () => crypto.randomBytes(ALGORITHM.SALT_BYTE_LEN);

/**
* 
* @param {Buffer} password - The password to be used for generating key
* 
* To be used when key needs to be generated based on password.
* The caller of this function has the responsibility to clear 
* the Buffer after the key generation to prevent the password 
* from lingering in the memory
*/
export const getKeyFromPassword = (password, salt) => {
  return crypto.scryptSync(password, salt, ALGORITHM.KEY_BYTE_LEN);
}

/**
* 
* @param {Buffer} messagetext - The clear text message to be encrypted
* @param {Buffer} key - The key to be used for encryption
* 
* The caller of this function has the responsibility to clear 
* the Buffer after the encryption to prevent the message text 
* and the key from lingering in the memory
*/
export const cryptoencrypt = (messagetext, key) => {
  const iv = getIV();
  const cipher = crypto.createCipheriv(
    ALGORITHM.BLOCK_CIPHER, key, iv,
    { 'authTagLength': ALGORITHM.AUTH_TAG_BYTE_LEN });
  let encryptedMessage = cipher.update(messagetext);
  encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);
  return Buffer.concat([iv, encryptedMessage, cipher.getAuthTag()]);
}

/**
* 
* @param {Buffer} ciphertext - Cipher text
* @param {Buffer} key - The key to be used for decryption
* 
* The caller of this function has the responsibility to clear 
* the Buffer after the decryption to prevent the message text 
* and the key from lingering in the memory
*/
export const cryptodecrypt = (ciphertext, key) => {
  const authTag = ciphertext.slice(-16);
  const iv = ciphertext.slice(0, 12);
  const encryptedMessage = ciphertext.slice(12, -16);
  const decipher = crypto.createDecipheriv(
    ALGORITHM.BLOCK_CIPHER, key, iv,
    { 'authTagLength': ALGORITHM.AUTH_TAG_BYTE_LEN });
  decipher.setAuthTag(authTag);
  let messagetext = decipher.update(encryptedMessage);
  messagetext = Buffer.concat([messagetext, decipher.final()]);
  return messagetext;
}

/**
 *
 *
 * @param {*} actionFunction
 * @param {string} [salt=""]
 * @param {number} [index=1] Value is the messagetext to be encryptedand decrypted. Use the index of value as the index property's value
 * @param {*} [encrypter=cryptoencrypt]
 * @return {*} 
 */
export const encrypt = function encrypt(actionFunction, salt = "", index = 1, encrypter = cryptoencrypt) {
  return function (...args) {
    let options = ["aes-256-ctr", "sha256", "base64", { logger: console.log }]
    args[index] = encrypter(args[index], salt, ...options);
    return actionFunction(...args);
  };
}

/**
 *
 *
 * @param {*} actionFunction
 * @param {string} [salt=""]
 * @param {number} [index=1] Value is the messagetext to be encryptedand decrypted. Use the index of value as the index property's value
 * @param {*} [decrypter=cryptodecrypt]
 * @return {*} 
 */
export const decrypt = function decrypt(actionFunction, salt = "", index = 1, decrypter = cryptodecrypt) {
  return function (...args) {
    let options = ["aes-256-ctr", "sha256", "base64", { logger: console.log }]
    let data = actionFunction(...args);
    args[index] = decrypter(data, salt, ...options);
    return args[index];
  };
}

/**
 *
 *
 * @param {*} actionFunction
 * @param {string} [salt=""]
 * @param {*} [encrypter=cryptoencrypt]
 * @return {*} 
 */
export const encryptRecursive = function encryptRecursive(actionFunction, salt = "", encrypter = cryptoencrypt) {
  return (...args) => actionFunction(...args).map(v => encrypter(v, salt));
}

/**
 *
 *
 * @param {*} actionFunction
 * @param {string} [salt=""]
 * @param {*} [decrypter=cryptodecrypt]
 * @return {*} 
 */
export const decryptRecursive = function decryptRecursive(actionFunction, salt = "", decrypter = cryptodecrypt) {
  return (...args) => actionFunction(...args).map(v => decrypter(v, salt));
}

export default {
  encrypt,
  decrypt,
  cryptoencrypt,
  cryptodecrypt,
  encryptRecursive,
  decryptRecursive,
  getRandomKey,
  getIV,
  getKeyFromPassword
}
