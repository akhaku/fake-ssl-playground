const {bytesToNumber, numberToBytes} = require('./utils');

const RecordVersion = {
  SSL_3_0: [3, 0],
  TLS_1_0: [3, 1],
  TLS_1_1: [3, 2],
  TLS_1_2: [3, 3],
};

const RecordType = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23,
};

class TlsRecord {
  constructor(recordType, recordVersion, message) {
    const length = message.getByteArray().length;
    if (length > 16384) {
      throw new Error('Cannot have Tls record of over 16KiB');
    }
    const lengthAsTwoBytes = numberToBytes(length, 2);
    // 5 byte header: record type, 2 * TLS version, 2 * length
    const header = [recordType, recordVersion[0], recordVersion[1], ...lengthAsTwoBytes];
    this.byteArray = [...header, ...message.getByteArray()];
  }

  getRecordType() {
    return this.byteArray[0];
  }

  getRecordVersion() {
    return [this.byteArray[1], this.byteArray[2]];
  }

  getLength() {
    return bytesToNumber(this.byteArray.slice(3, 5));
  }

  getByteArray() {
    return this.byteArray;
  }
}

const HandshakeType = {
  HELLO_REQUEST: 0,
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  CERTIFICATE: 11,
  SERVER_KEY_EXCHANGE: 12,
  CERTIFICATE_REQUEST: 13,
  SERVER_DONE: 14,
  CERTIFICATE_VERIFY: 15,
  CLIENT_KEY_EXCHANGE: 16,
  FINISHED: 20,
};

class HandshakeMessage {
  constructor(handshakeType, message) {
    const length = message.getByteArray().length;
    const lengthAsThreeBytes = numberToBytes(length, 3);
    // 4 byte header: record type, 3 * length
    const header = [handshakeType, ...lengthAsThreeBytes];
    this.byteArray = [...header, ...message.getByteArray()];
  }

  getHandshakeType() {
    return this.byteArray[0];
  }

  getLength() {
    return bytesToNumber(this.byteArray.slice(1, 4));
  }
}

class CipherSuites {
  constructor(cipherIds) { // list of cipher IDs
    const length = cipherIds.length * 2;
    const lengthArray = numberToBytes(length, 2);
    let cipherIdsArray = [];
    cipherIds.forEach(cipherId => {
      cipherIdsArray = [...cipherIdsArray, ...numberToBytes(cipherId, 2)];
    });
    if (length !== cipherIdsArray.length) {
      throw new Error('Unexpected exception with cipher suites');
    }
    this.byteArray = [...lengthArray, ...cipherIdsArray];
  }

  getCipherIds() {
    const length = this.getLength();
    const ret = [];
    let currentIndex = 2;
    while (currentIndex < length + 2) {
      ret.push(bytesToNumber(this.byteArray.slice(currentIndex, currentIndex + 2)));
      currentIndex += 2;
    }
    return ret;
  }

  getLength() {
    return bytesToNumber(this.byteArray.slice(0, 2));
  }

  getByteArray() {
    return this.byteArray;
  }
}

class Extensions {
  constructor(extensions) { // list of {id: id, data: [data]}
    const length = extensions.reduce((acc, curr) => {
      const idLength = 2;
      const dataLengthLength = 2;
      const dataLength = curr.data.length;
      return acc + idLength + dataLengthLength + dataLength;
    }, 0);
    const lengthArray = numberToBytes(length, 2);
    let extensionsArray = [];
    extensions.forEach(extension => {
      extensionsArray = [
        ...extensionsArray,
        ...numberToBytes(extension.id, 2),
        ...numberToBytes(extension.data.length, 2),
        ...extension.data]
    });
    if (length != extensionsArray.length) {
      throw new Error('Unexpected exception with extensions');
    }
    this.byteArray = [...lengthArray, ...extensionsArray];
  }

  getExtensions() {
    const length = this.getLength();
    const ret = [];
    let currentIndex = 2;
    while (currentIndex < length + 2) {
      const id = bytesToNumber(this.byteArray.slice(currentIndex, currentIndex + 2));
      currentIndex += 2;
      const dataLength = bytesToNumber(this.byteArray.slice(currentIndex, currentIndex + 2));
      console.log(`dataLength: ${dataLength}`);
      currentIndex += 2;
      const data = this.byteArray.slice(currentIndex, currentIndex + dataLength);
      console.log(`slices: ${data}`);
      currentIndex += dataLength;
      ret.push({id, data});
    }
    return ret;
  }

  getLength() {
    return bytesToNumber(this.byteArray.slice(0, 2));
  }

  getByteArray() {
    return this.byteArray;
  }
}

class ClientHello {
  constructor(recordVersion, randomBytes, sessionId, cipherSuites, compressionMethods, extensions) {
    if (randomBytes.length != 32) {
      throw new Error('Random bytes must be of length 32');
    }
    // TODO handle session ID
    if (sessionId.length !== 0) {
      throw new Error('Non-empty session IDs currently unsupported');
    }
    if (compressionMethods !== [0, 1, 0]) {
      throw new Error('Non-empty compression currently unsupported');
    }
    const sessionIdAsArray = [0];
    this.byteArray = [
      ...recordVersion,
      ...randomBytes,
      ...sessionIdAsArray,
      ...cipherSuites.getByteArray(),
      ...extensions.getByteArray(),
    ];
  }

  getByteArray() {
    return this.byteArray;
  }
}

module.exports = {
  CipherSuites,
  Extensions,
  HandshakeMessage,
  RecordType,
  RecordVersion,
  TlsRecord,
};
