import { generateKeyPair } from './components/rsa-wrapper.js';

await generateKeyPair('server');
await generateKeyPair('client');

console.log('Keys generated ...');
