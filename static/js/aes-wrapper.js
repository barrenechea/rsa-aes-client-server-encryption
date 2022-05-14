(function () {

  'use strict';

  const crypto = window.crypto.subtle;

  // wrapper for importing AES key for using with crypto library
  const importPublicKey = async (key) => {
    const cryptoKey = await crypto.importKey("raw", converterWrapper.base64StringToArrayBuffer(key),
      {
        name: "AES-CBC"
      },
      false, //whether the key is extractable (i.e. can be used in exportKey)
      ["encrypt", "decrypt"] //can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
    );

    return cryptoKey;
  };

  // separate initialization vector from message
  const separateVectorFromData = (data) => {
    const iv = data.slice(-24);
    const message = data.substring(0, data.length - 24)

    return {
      iv: iv,
      message: message
    };
  };

  // add initialization vector to message
  const getMessageWithIv = (message, iv) => {
    return converterWrapper.arrayBufferToBase64String(message) + converterWrapper.arrayBufferToBase64String(iv);
  }


  const encryptMessage = async (key, message) => {
    const iv = window.crypto.getRandomValues(new Uint8Array(16));

    const cryptoKey = await importPublicKey(key);

    const encrypted = await crypto.encrypt(
      {
        name: "AES-CBC",
        //Don't re-use initialization vectors!
        //Always generate a new iv every time your encrypt!
        iv: iv
      },
      cryptoKey, //from generateKey or importKey above
      converterWrapper.str2abUtf8(message) //ArrayBuffer of data you want to encrypt
    );

    return getMessageWithIv(encrypted, iv);
  };

  const decryptMessage = async (key, message) => {
    const data = aesWrapper.separateVectorFromData(message);

    const cryptoKey = await importPublicKey(key);

    const decrypted = await crypto.decrypt(
      {
        name: "AES-CBC",
        iv: converterWrapper.base64StringToArrayBuffer(data['iv']),
      },
      cryptoKey, //from generateKey or importKey above
      converterWrapper.base64StringToArrayBuffer(data['message']) //ArrayBuffer of data you want to encrypt
    )

    return converterWrapper.arrayBufferToUtf8(decrypted);
  }

  window.aesWrapper = {
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,
    importPublicKey: importPublicKey,
    separateVectorFromData: separateVectorFromData,
  }

}());