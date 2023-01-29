const {
  CipherSuites,
  ClientHello,
  Extensions,
  HandshakeMessage,
  HandshakeType,
  RecordType,
  RecordVersion,
  TlsRecord,
} = require('./types');
const {randomBytes} = require('./utils');

const clientCipherSuites = CipherSuites.create([163, 160, 918]);
const clientExtensions = Extensions.create([]);
const clientTlsVersion = RecordVersion.TLS_1_2;

const createClientHello = () => {
  const rand = randomBytes();
  const clientHello = ClientHello.create(
    clientTlsVersion,
    rand,
    [], // session ID
    clientCipherSuites,
    [0, 1, 0], // no compression
    clientExtensions);
  const handshakeMessage = HandshakeMessage.create(HandshakeType.CLIENT_HELLO, clientHello);
  return TlsRecord.create(RecordType.HANDSHAKE, clientTlsVersion, handshakeMessage);
};

module.exports = {createClientHello};
