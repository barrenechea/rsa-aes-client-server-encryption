(function () {

  'use strict';

  const crypto = window.crypto.subtle;
  const rsaParams = { name: "RSA-OAEP", hash: { name: "SHA-1" } };

  const importPublicKey = async (keyInPemFormat) => {
    let key = converterWrapper.convertPemToBinary2(keyInPemFormat);
    key = converterWrapper.base64StringToArrayBuffer(key);

    return crypto.importKey('spki', key, rsaParams, false, ["encrypt"]);
  };

  const importPrivateKey = async (keyInPemFormat) => {
    let key = converterWrapper.convertPemToBinary2(keyInPemFormat);
    key = converterWrapper.base64StringToArrayBuffer(key);

    return crypto.importKey('pkcs8', key, rsaParams, false, ["decrypt"]);
  };

  const publicEncrypt = async (keyInPemFormat, message) => {
    const cryptoKey = await importPublicKey(keyInPemFormat);
    const encrypted = await crypto.encrypt(rsaParams, cryptoKey, converterWrapper.str2abUtf8(message));

    return converterWrapper.arrayBufferToBase64String(encrypted);
  };

  const privateDecrypt = async (keyInPemFormat, encryptedBase64Message) => {
    const cryptoKey = await importPrivateKey(keyInPemFormat);
    const decrypted = await crypto.decrypt(rsaParams, cryptoKey, converterWrapper.base64StringToArrayBuffer(encryptedBase64Message));

    return converterWrapper.arrayBufferToUtf8(decrypted);
  };

  window.rsaWrapper = {
    importPrivateKey: importPrivateKey,
    importPublicKey: importPublicKey,
    privateDecrypt: privateDecrypt,
    publicEncrypt: publicEncrypt
  };

}());
