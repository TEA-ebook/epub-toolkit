import pako from 'pako';
import forge from 'node-forge';
import {isEmpty} from './utils';

const IV_BYTES_SIZE = 16;
const CBC_CHUNK_SIZE = 1024 * 32; // best perf with 32ko chunks
const ZIP_COMPRESSION_METHOD = 8;

export const PROTECTION_METHODS = {
  ADOBE_DRM: 'http://ns.adobe.com/adept',
  ADOBE_FONT: 'http://ns.adobe.com/pdf/enc#RC',
  LCP: 'http://readium.org/2014/01/lcp#EncryptedContentKey',
  IDPF_FONT: 'http://www.idpf.org/2008/embedding',
  UNKNOWN: 'unknown'
};

class Lcp {
  constructor() {
    this.contextList = {};
  }

  /**
   * Deciphers data and outputs binary data
   *
   * @param fetchMode
   * @param fileData
   * @param protection
   * @param license
   * @param key
   * @returns {Promise}
   */
  async decipherFile(fetchMode, fileData, protection, license, key) {
    const decipheredRawData = await decipherData.call(this, fileData, license, key);

    if (!isEmpty(protection) && protection['compressionMethod'] === ZIP_COMPRESSION_METHOD) {
      return fetchMode === 'text' ? unzipToString(decipheredRawData) : unzipToArrayBuffer(decipheredRawData);
    }

    return fetchMode === 'text' ? arrayBuffer2Binary(decipheredRawData) : decipheredRawData;
  }

  /**
   * Deciphers data and outputs binary data
   *
   * @param fileData
   * @param protection
   * @param license
   * @param key
   * @returns {Promise<String>}
   */
  async decipherTextFile(fileData, protection, license, key) {
    return this.decipherFile('text', fileData, protection, license, key);
  }

  /**
   * Deciphers data and outputs ArrayBuffer
   *
   * @param fileData
   * @param protection
   * @param license
   * @param key
   * @returns {Promise<ArrayBuffer>}
   */
  async decipherBinaryFile(fileData, protection, license, key) {
    return this.decipherFile('arraybuffer', fileData, protection, license, key);
  }

  /**
   * Get the first valid user key for given LCP license
   *
   * @param {array} keys - the decrypted LCP keys
   * @param {object} license - the parsed LCP license of epub
   * @return {Promise} A promise that resolves with a valid user key if any
   */
  async getValidUserKey(license, keys) {
    if (isEmpty(license) || isEmpty(keys)) {
      return;
    }

    const validKeys = [];
    for (const key of keys) {
      const valid = await this.checkValidity(key, license);
      if (valid) {
        validKeys.push(key);
      }
    }
    return validKeys.pop();
  }

  /**
   * Test user key against epub LCP license
   *
   * @param {string} userKey
   * @param {object} license
   * @return {Promise} A promise that resolves with the user key, rejects if not valid
   */
  async checkValidity(userKey, license) {
    const userKeyCheck = license.encryption.user_key.key_check;

    // Decrypt and compare it to license ID
    try {
      const userKeyCheckDecrypted = await decipher(forge.util.hexToBytes(userKey), forge.util.decode64(userKeyCheck));
      return license.id === userKeyCheckDecrypted;
    } catch (error) {
      console.warn(error);
      return false;
    }
  }
}

export default new Lcp();

/**
 * Creates or returns a LCP context for file data decipher
 *
 * @param license {String}: the json string of the license
 * @param key {String}: a valid user key
 * @returns {Promise<Object>}
 */
async function getContext(license, key) {
  let context = this.contextList[`${license.id}:${key}`];
  if (context) {
    return context;
  }

  context = await createContext(license, key);
  this.contextList[`${license['id']}:${key}`] = context;

  return context;
}

async function createContext(license, userKey) {
  return {
    contentKey: await getContentKey(license, userKey)
  };
}

async function decipherData(fileData, license, userKey) {
  const context = await getContext.call(this, license, userKey);
  return decipher(context.contentKey, fileData, 'arraybuffer');
}

function decipher(key, encryptedData, dataType) {
  if (dataType === 'arraybuffer') {
    return aesDecipherArrayBuffer(key, encryptedData);
  }
  if (dataType === 'blob') {
    return blobToArrayBuffer(encryptedData)
      .then(arrayBuffer => aesDecipherArrayBuffer(key, arrayBuffer));
  }
  return aesDecipherBinary(key, encryptedData);
}

function getContentKey(license, userKey) {
  const contentKeyEncrypted = forge.util.decode64(license.encryption.content_key.encrypted_value);
  return decipher(forge.util.hexToBytes(userKey), contentKeyEncrypted);
}

function aesDecipherArrayBuffer(key, encryptedArrayBuffer) {
  try {
    const decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({iv: forge.util.createBuffer(encryptedArrayBuffer.slice(0, IV_BYTES_SIZE)).data});

    const length = encryptedArrayBuffer.length || encryptedArrayBuffer.byteLength;

    let index = IV_BYTES_SIZE;
    let realSize = 0;

    const decryptedBuffer = new Uint8Array(length);
    do {
      const bytes = decipher.output.getBytes();
      if (bytes.length > 0) {
        const binArray = binary2BinArray(bytes);
        decryptedBuffer.set(binArray, index - CBC_CHUNK_SIZE - IV_BYTES_SIZE);
        realSize += bytes.length;
      }

      const buf = forge.util.createBuffer(encryptedArrayBuffer.slice(index, index + CBC_CHUNK_SIZE));
      decipher.update(buf);
      index += CBC_CHUNK_SIZE;
    } while (index < length);

    decipher.finish();

    const bytes = decipher.output.getBytes();
    realSize += bytes.length;
    decryptedBuffer.set(binary2BinArray(bytes), index - CBC_CHUNK_SIZE - IV_BYTES_SIZE);

    return decryptedBuffer.slice(0, realSize);
  } catch (e) {
    throw new Error('Decipher failed: ' + e.message);
  }
}

function aesDecipherBinary(key, encryptedBytes) {
  try {
    const decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({iv: encryptedBytes.substring(0, IV_BYTES_SIZE)});

    const length = encryptedBytes.length;
    const chunkSize = CBC_CHUNK_SIZE;
    let index = IV_BYTES_SIZE;
    let decrypted = '';

    do {
      decrypted += decipher.output.getBytes();
      const buf = forge.util.createBuffer(encryptedBytes.substr(index, chunkSize));
      decipher.update(buf);
      index += chunkSize;
    } while (index < length);

    decipher.finish();
    decrypted += decipher.output.getBytes();

    return decrypted;
  } catch (e) {
    throw new Error('Key is invalid: ' + e.message);
  }
}

function blobToArrayBuffer(blob) {
  return new Promise((resolve, reject) => {
    const fileReader = new FileReader();
    fileReader.onload = function () {
      resolve(this.result);
    };
    fileReader.onerror = reject;
    fileReader.readAsArrayBuffer(blob);
  });
}

function binary2BinArray(binary) {
  const uint8Array = new Uint8Array(binary.length);
  for (let i = 0; i < uint8Array.length; i++) {
    uint8Array[i] = binary.charCodeAt(i);
  }
  return uint8Array;
}

function arrayBuffer2Binary(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const length = bytes.byteLength;
  for (let i = 0; i < length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return binary;
}

/**
 * @param data ArrayBuffer
 * @returns {ArrayBuffer}
 */
function unzipToArrayBuffer(data) {
  return pako.inflateRaw(data, {to: 'array'});
}

/**
 *
 * @param data ArrayBuffer
 * @returns {String}
 */
function unzipToString(data) {
  return pako.inflateRaw(data, {to: 'string'});
}
