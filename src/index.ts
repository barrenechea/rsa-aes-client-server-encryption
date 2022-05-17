import { Server } from 'http';
import express from 'express';
import { Server as SocketIOServer } from 'socket.io';
import { initLoadServerKeys, encryptRSA, decryptRSA } from './components/rsa-wrapper.js';
import { generateKey, createAesMessage, decryptAES } from './components/aes-wrapper.js';

const app = express();
const http = new Server(app);
const io = new SocketIOServer(http);

const keys = await initLoadServerKeys();

// middleware for static processing
app.use(express.static('./static'));

// web socket connection event
io.on('connection', async (socket) => {
  // Test sending to client dummy RSA message
  const encrypted = await encryptRSA(keys.clientPub, 'Hello RSA message from client to server');
  socket.emit('rsa server encrypted message', encrypted);

  // Test accepting dummy RSA message from client
  socket.on('rsa client encrypted message', async (data: string) => {
    console.log('Server received RSA message from client');
    console.log('Encrypted message:', data);
    console.log('Decrypted message:', await decryptRSA(keys.serverPrivate, data));
  });

  // Test AES key sending
  const aesKey = await generateKey();
  const encryptedAesKey = await encryptRSA(keys.clientPub, (aesKey.toString('base64')));
  socket.emit('send key from server to client', encryptedAesKey);

  // Test accepting dummy AES key message
  socket.on('aes client encrypted message', async (data: string) => {
    console.log('Decrypted message:', decryptAES(aesKey, data));

    // Test send client dummy AES message
    const message = await createAesMessage(aesKey, 'Server AES message');
    socket.emit('aes server encrypted message', message);
  });
});

http.listen(3000, async () => {
  console.log('listening on *:3000');

  const encrypted = await encryptRSA(keys.serverPub, 'Server init hello');
  console.log('Encrypted RSA string:', encrypted);
  const decrypted = await decryptRSA(keys.serverPrivate, encrypted);
  console.log('Decrypted RSA string:', decrypted);
});
