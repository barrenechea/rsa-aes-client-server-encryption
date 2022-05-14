import path from 'node:path';
import fs from 'node:fs/promises';
import { webcrypto } from 'node:crypto';

export const initLoadServerKeys = async () => {
  const [serverPub, serverPrivate, clientPub] = await Promise.all([
    fs.readFile(path.resolve('keys', 'server.public.pem')),
    fs.readFile(path.resolve('keys', 'server.private.pem')),
    fs.readFile(path.resolve('keys', 'client.public.pem'))
  ]);

  const serverPubString = serverPub.toString('utf8').replace(/^-+(BEGIN|END) PUBLIC KEY-+\n/, '').replace(/\n/g, '');
  const serverPrivateString = serverPrivate.toString('utf8').replace(/^-+(BEGIN|END) PRIVATE KEY-+\n/, '').replace(/\n/g, '');
  const clientPubString = clientPub.toString('utf8').replace(/^-+(BEGIN|END) PUBLIC KEY-+\n/, '').replace(/\n/g, '');

  const serverPubBuffer = Buffer.from(serverPubString, 'base64');
  const serverPrivateBuffer = Buffer.from(serverPrivateString, 'base64');
  const clientPubBuffer = Buffer.from(clientPubString, 'base64');

  const serverPubKey = await webcrypto.subtle.importKey('spki', serverPubBuffer, { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }, true, ['encrypt', 'wrapKey']);
  const serverPrivateKey = await webcrypto.subtle.importKey('pkcs8', serverPrivateBuffer, { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }, true, ['decrypt', 'unwrapKey']);
  const clientPubKey = await webcrypto.subtle.importKey('spki', clientPubBuffer, { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }, true, ['encrypt', 'wrapKey']);

  return {
    serverPub: serverPubKey,
    serverPrivate: serverPrivateKey,
    clientPub: clientPubKey
  };
};

export const generateKeyPair = async (direction: string): Promise<void> => {
  const options = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: 'SHA-256' },
  };

  const keys = await webcrypto.subtle.generateKey(options, true, ['sign', 'verify']);

  const [publicKey, privateKey] = await Promise.all([
    webcrypto.subtle.exportKey('spki', keys.publicKey),
    webcrypto.subtle.exportKey('pkcs8', keys.privateKey),
  ]);

  const base64PubKey = Buffer.from(publicKey).toString('base64').match(/.{1,64}/g)!.join('\n');
  const base64PrivKey = Buffer.from(privateKey).toString('base64').match(/.{1,64}/g)!.join('\n');

  const publicKeyFile = `-----BEGIN PUBLIC KEY-----\n${base64PubKey}\n-----END PUBLIC KEY-----\n`;
  const privateKeyFile = `-----BEGIN PRIVATE KEY-----\n${base64PrivKey}\n-----END PRIVATE KEY-----\n`;

  await Promise.all([
    fs.writeFile(path.resolve('keys', `${direction}.public.pem`), publicKeyFile),
    fs.writeFile(path.resolve('keys', `${direction}.private.pem`), privateKeyFile),
  ]);
};

export const encryptRSA = async (publicKey: CryptoKey, message: string): Promise<string> => {
  const decryptedBuffer = Buffer.from(message);
  const encryptedBuffer = await webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, decryptedBuffer);
  
  return Buffer.from(encryptedBuffer).toString('base64');
};

export const decryptRSA = async (privateKey: CryptoKey, base64Message: string): Promise<string> => {
  const encryptedBuffer = Buffer.from(base64Message, 'base64');
  const decryptedBuffer = await webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedBuffer);

  return Buffer.from(decryptedBuffer).toString();
}