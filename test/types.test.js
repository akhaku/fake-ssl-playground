const {RecordVersion, RecordType, TlsRecordHeader} = require('../src/types');

describe('TlsRecordHeader', () => {
  test('Can store and retrieve values', () => {
    const header = new TlsRecordHeader(RecordType.HANDSHAKE, RecordVersion.TLS_1_2, 12345);
    expect(header.getRecordType()).toBe(RecordType.HANDSHAKE);
    expect(header.getRecordVersion()).toStrictEqual(RecordVersion.TLS_1_2);
    expect(header.getLength()).toBe(12345);
  });
});
