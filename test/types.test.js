const {
  CipherSuites,
  ClientHello,
  Extensions,
  HandshakeMessage,
  HandshakeType,
  RecordType,
  RecordVersion,
  TlsRecord,
} = require('../src/types');
const {randomBytes} = require('../src/utils');

class SimpleMessage {
  constructor(size) {
    this.byteArray = [];
    while (size-- > 0) {
      this.byteArray.push(0);
    }
  }

  getByteArray() {
    return this.byteArray;
  }
}

describe('TlsRecord', () => {
  test('Can store and retrieve values', () => {
    const record = TlsRecord.create(RecordType.HANDSHAKE,
      RecordVersion.TLS_1_2,
      new SimpleMessage(12345));
    expect(record.getRecordType()).toBe(RecordType.HANDSHAKE);
    expect(record.getRecordVersion()).toStrictEqual(RecordVersion.TLS_1_2);
    expect(record.getLength()).toBe(12345);
    expect(record.getByteArray().length).toBe(5 + 12345);
  });

  test('Can store CLIENT_HELLO message', () => {
    const tlsRecordType = RecordType.HANDSHAKE;
    const tlsVersion = RecordVersion.TLS_1_1;
    const rand = randomBytes();
    const extensions = Extensions.create([{id: 16, data: [0, 1, 6, 0]}]);
    const clientHello = ClientHello.create(
      tlsVersion,
      rand,
      [],
      CipherSuites.create([]),
      [0, 1, 0],
      extensions);
    const handshakeType = HandshakeType.CLIENT_HELLO;
    const handshakeMessage = HandshakeMessage.create(handshakeType, clientHello);
    const tlsRecord = TlsRecord.create(tlsRecordType, tlsVersion, handshakeMessage);

    expect(tlsRecord.getRecordType()).toBe(tlsRecordType);
    expect(tlsRecord.getRecordVersion()).toStrictEqual(tlsVersion);
  });
});

describe('CipherSuites', () => {
  test('Can store and retrieve values', () => {
    let cipherSuites = CipherSuites.create([]);
    expect(cipherSuites.getLength()).toBe(0);
    expect(cipherSuites.getCipherIds()).toStrictEqual([]);

    const cipherIds = [1, 10, 100, 1000, 10000];
    cipherSuites = CipherSuites.create(cipherIds);
    expect(cipherSuites.getLength()).toBe(10);
    expect(cipherSuites.getCipherIds()).toStrictEqual(cipherIds);
  });
});

describe('Extensions', () => {
  test('Can store and retrieve values', () => {
    let extensions = Extensions.create([]);
    expect(extensions.getLength()).toBe(0);
    expect(extensions.getExtensions()).toStrictEqual([]);

    let payload = [{id: 10, data: [0, 1, 19]}];
    extensions = Extensions.create(payload);
    expect(extensions.getLength()).toBe(7);
    expect(extensions.getExtensions()).toStrictEqual(payload);

    payload = [{id: 19, data: [8, 1, 19]}, {id: 8, data: [1]}];
    extensions = Extensions.create(payload);
    expect(extensions.getLength()).toBe(12);
    expect(extensions.getExtensions()).toStrictEqual(payload);
  });
});
