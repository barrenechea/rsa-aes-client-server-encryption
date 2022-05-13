NodeJS and browser RSA / AES encryption Example
================================================

Description
------------
An example of exchanging encrypted messages between server and client using NodeJS' Express framework and Socket.IO infrastructure for best visualization.
The client-side encryption is written with CryptoAPI.
The Server-side encryption is written with Node native crypto.

[READ DETAILED INFO IN THE ARTICLE](https://medium.com/@weblab_tech/encrypted-client-server-communication-protection-of-privacy-and-integrity-with-aes-and-rsa-in-c7b180fe614e#.6pvs68jnn)

Requirements
------------
NodeJS >= 16

Generate keys
---------------
~~~~~~~~~~~~~~~~~~
npm run generate
~~~~~~~~~~~~~~~~~~
Then overwrite textarea values in static/index.html

Run
---
~~~~~~~~~~~~~~~~~~
npm start
~~~~~~~~~~~~~~~~~~
Starts a web server with WebSockets on port 3000
