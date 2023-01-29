const bytesToNumber = bytes => {
  let num = 0;
  for (let i = 0; i < bytes.length; i++) {
    num += bytes[bytes.length - i - 1] << (8 * i)
  }
  return num;
};

const numberToBytes = (num, numBytes) => {
  if (numBytes <= 0) {
    throw new Error(`Invalid numBytes ${numBytes}`);
  }
  const ret = [];
  let n = num;
  do {
    ret.unshift(n & 0b11111111);
    n = n >> 8;
  } while (n >= 0 && ret.length < numBytes);
  if (ret.length !== numBytes) {
    throw new Error(`${num} did not fit into ${numBytes} bytes`);
  }
  return ret;
};
module.exports = {bytesToNumber, numberToBytes};
