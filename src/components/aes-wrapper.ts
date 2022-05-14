import crypto from 'node:crypto';
import { promisify } from 'node:util';

const randomBytesAsync = promisify(crypto.randomBytes);

/**
   * Generates a random initialization vector
   * @returns initialization vector
   */
const generateIv = (): Promise<Buffer> => randomBytesAsync(16);

/**
   * separate initialization vector from message
   * @param data data to separate
   */
const parseRawMessage = (data: string): { iv: Buffer, message: Buffer } => {
  const iv = data.slice(-24);
  const message = data.substring(0, data.length - 24);

  return {
    iv: Buffer.from(iv, 'base64'),
    message: Buffer.from(message, 'base64'),
  };
};

/**
   * add initialization vector to message
   * @param iv initialization vector
   * @param base64Message base64 encrypted message
   * @returns base64 encrypted message with iv
   */
const addIvToBody = (iv: Buffer, base64Message: string): string => {
  const base64Iv = iv.toString('base64');

  return `${base64Message}${base64Iv}`;
};

/**
 * Generates a random AES key
 * @returns AES key
 */
export const generateKey = (): Promise<Buffer> => randomBytesAsync(32);

/**
   * create AES message
   * @param key AES key
   * @param iv initialization vector
   * @param text message to encrypt
   * @returns base64 encoded AES message
   */
export const encrypt = (key: Buffer, iv: Buffer, text: string): string => {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(text)), cipher.final()]);

  return encrypted.toString('base64');
};

/**
   * decrypts AES message
   * @param key AES key
   * @param text base64 encoded AES message
   * @returns decrypted message
   */
export const decryptAES = (key: Buffer, text: string): string => {
  const data = parseRawMessage(text);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, data.iv);
  const decrypted = Buffer.concat([decipher.update(data.message), decipher.final()]);

  return decrypted.toString('utf8');
};

/**
   * create an AES encrypted message
   * @param aesKey AES key
   * @param message message to encrypt
   * @returns base64 encoded AES message with attached iv
   */
export const createAesMessage = async (aesKey: Buffer, message: string): Promise<string> => {
  const aesIv = await generateIv();
  const encryptedMessage = encrypt(aesKey, aesIv, message);

  return addIvToBody(aesIv, encryptedMessage);
};
