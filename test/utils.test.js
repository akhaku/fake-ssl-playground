const {bytesToNumber, numberToBytes} = require('../src/utils');

describe('bytesToNumber', () => {
  test('Can convert single-byte numbers', () => {
    expect(bytesToNumber([5])).toBe(5);
    expect(bytesToNumber([0, 5])).toBe(5);
    expect(bytesToNumber([0, 0, 5])).toBe(5);
    expect(bytesToNumber([24])).toBe(24);
    expect(bytesToNumber([255])).toBe(255);
  });

  test('Can convert multi-byte numbers', () => {
    expect(bytesToNumber([5, 0])).toBe(1280);
    expect(bytesToNumber([5, 1])).toBe(1281);
    expect(bytesToNumber([1, 1, 0])).toBe(65536 + 256);
  });
});

describe('numberToBytes', () => {
  test('Can convert small numbers', () => {
    expect(numberToBytes(5, 1)).toStrictEqual([5]);
    expect(numberToBytes(5, 2)).toStrictEqual([0, 5]);
    expect(numberToBytes(15, 1)).toStrictEqual([15]);
    expect(numberToBytes(15, 3)).toStrictEqual([0, 0, 15]);
  });

  test('Can convert larger numbers', () => {
    expect(numberToBytes(256, 2)).toStrictEqual([1, 0]);
    expect(numberToBytes(257, 2)).toStrictEqual([1, 1]);
    expect(numberToBytes(257, 3)).toStrictEqual([0, 1, 1]);
  });
});
