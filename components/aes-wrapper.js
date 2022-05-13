import crypto from 'node:crypto';
import { promisify } from 'node:util';

const randomBytesAsync = promisify(crypto.randomBytes);

/**
   * Generates a random initialization vector
   * @returns {Buffer} initialization vector
   */
const generateIv = () => randomBytesAsync(16);

/**
   * separate initialization vector from message
   * @param {string} data data to separate
   */
const parseRawMessage = (data) => {
  const iv = data.slice(-24);
  const message = data.substring(0, data.length - 24);

  return {
    iv: Buffer.from(iv, 'base64'),
    message: Buffer.from(message, 'base64'),
  };
};

/**
   * add initialization vector to message
   * @param {Buffer} iv initialization vector
   * @param {string} base64Message base64 encrypted message
   * @returns {string} base64 encrypted message with iv
   */
const addIvToBody = (iv, base64Message) => {
  const base64Iv = iv.toString('base64');

  return `${base64Message}${base64Iv}`;
};

/**
 * Generates a random AES key
 * @returns {Buffer} AES key
 */
export const generateKey = () => randomBytesAsync(32);

/**
   * create AES message
   * @param {Buffer} key AES key
   * @param {Buffer} iv initialization vector
   * @param {string} text message to encrypt
   * @returns base64 encoded AES message
   */
export const encrypt = (key, iv, text) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(text)), cipher.final()]);

  return encrypted.toString('base64');
};

/**
   * decrypts AES message
   * @param {Buffer} key AES key
   * @param {string} text base64 encoded AES message
   * @returns {string}  decrypted message
   */
export const decryptAES = (key, text) => {
  const data = parseRawMessage(text);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, data.iv);
  const decrypted = Buffer.concat([decipher.update(data.message), decipher.final()]);

  return decrypted.toString('utf8');
};

/**
   * create an AES encrypted message
   * @param {Buffer} aesKey AES key
   * @param {string} message message to encrypt
   * @returns {Buffer} base64 encoded AES message with attached iv
   */
export const createAesMessage = async (aesKey, message) => {
  const aesIv = await generateIv();
  const encryptedMessage = encrypt(aesKey, aesIv, message);

  return addIvToBody(aesIv, encryptedMessage);
};
