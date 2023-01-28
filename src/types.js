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

class TlsRecordHeader {
  constructor(recordType, recordVersion, length) {
    const lengthAsTwoBytes = [length >> 8, length & 0b11111111]
    this.bytearray = [recordType, recordVersion[0], recordVersion[1], ...lengthAsTwoBytes];
  }

  getRecordType() {
    return this.bytearray[0];
  }

  getRecordVersion() {
    return [this.bytearray[1], this.bytearray[2]];
  }

  getLength() {
    return (this.bytearray[3] << 8) + this.bytearray[4];
  }
}

module.exports = {RecordVersion, RecordType, TlsRecordHeader};
