import fs from 'fs/promises';
import { resolve } from 'path';
import { generateKeyPair } from './components/rsa-wrapper.js';

const keysPath = resolve('keys');
const folderExists = !!(await fs.stat(keysPath).catch(e => false));
if (!folderExists) await fs.mkdir(keysPath);

await generateKeyPair('server');
await generateKeyPair('client');

console.log('Keys generated ...');
