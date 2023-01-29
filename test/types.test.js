const {
  CipherSuites,
  Extensions,
  RecordType,
  RecordVersion,
  TlsRecord,
} = require('../src/types');

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
    const record = new TlsRecord(RecordType.HANDSHAKE,
      RecordVersion.TLS_1_2,
      new SimpleMessage(12345));
    expect(record.getRecordType()).toBe(RecordType.HANDSHAKE);
    expect(record.getRecordVersion()).toStrictEqual(RecordVersion.TLS_1_2);
    expect(record.getLength()).toBe(12345);
    expect(record.getByteArray().length).toBe(5 + 12345);
  });
});

describe('CipherSuites', () => {
  test('Can store and retrieve values', () => {
    let cipherSuites = new CipherSuites([]);
    expect(cipherSuites.getLength()).toBe(0);
    expect(cipherSuites.getCipherIds()).toStrictEqual([]);

    const cipherIds = [1, 10, 100, 1000, 10000];
    cipherSuites = new CipherSuites(cipherIds);
    expect(cipherSuites.getLength()).toBe(10);
    expect(cipherSuites.getCipherIds()).toStrictEqual(cipherIds);
  });
});

describe('Extensions', () => {
  test('Can store and retrieve values', () => {
    let extensions = new Extensions([]);
    expect(extensions.getLength()).toBe(0);
    expect(extensions.getExtensions()).toStrictEqual([]);

    let payload = [{id: 10, data: [0, 1, 19]}];
    extensions = new Extensions(payload);
    expect(extensions.getLength()).toBe(7);
    expect(extensions.getExtensions()).toStrictEqual(payload);

    payload = [{id: 19, data: [8, 1, 19]}, {id: 8, data: [1]}];
    extensions = new Extensions(payload);
    expect(extensions.getLength()).toBe(12);
    expect(extensions.getExtensions()).toStrictEqual(payload);
  });
});
