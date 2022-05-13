import path from 'node:path';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const generateKeyPairAsync = promisify(crypto.generateKeyPair);

export const initLoadServerKeys = async () => {
  const [serverPub, serverPrivate, clientPub] = await Promise.all([
    fs.readFile(path.resolve('keys', 'server.public.pem')),
    fs.readFile(path.resolve('keys', 'server.private.pem')),
    fs.readFile(path.resolve('keys', 'client.public.pem'))
  ]);

  return {
    serverPub,
    serverPrivate,
    clientPub,
  };
};

export const generateKeyPair = async (direction) => {
  const keys = await generateKeyPairAsync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  await Promise.all([
    fs.writeFile(path.resolve('keys', `${direction}.private.pem`), keys.privateKey),
    fs.writeFile(path.resolve('keys', `${direction}.public.pem`), keys.publicKey)
  ]);
};

export const encryptRSA = (publicKey, message) => {
  const decryptedBuffer = Buffer.from(message);
  const encryptedBuffer = crypto.publicEncrypt({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  }, decryptedBuffer);

  return encryptedBuffer.toString('base64');
};

export const decryptRSA = (privateKey, base64Message) => {
  const encryptedBuffer = Buffer.from(base64Message, 'base64');
  const decryptedBuffer = crypto.privateDecrypt({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  }, encryptedBuffer);

  return decryptedBuffer.toString();
};
