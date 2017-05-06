const mnemonic = require('mnemonic-browser');
const bitcore = require('./deps/bitcore-lib');

const cryptoRandom = () => { // browser
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return Math.abs(array[0] / 0xFFFFFFFF);
};

/* const cryptoRandom = () => { // node; XXX not supported -- if we ever want this on the backend we need to figure out the isomorphic import
  const array = new Uint32Array(1);
  const setArray = new Uint8Array(array.buffer);
  setArray.set(crypto.randomBytes(setArray.byteLength));
  return Math.abs(array[0] / 0xFFFFFFFF);
}; */

const makeWords = () => {
  const result = Array(12);
  for (let i = 0; i < result.length; i++) {
    result[i] = mnemonic.words[Math.floor(cryptoRandom() * mnemonic.words.length)];
  }
  return result.join(' ');
};
const _parseWords = words => {
  const m = mnemonic.fromWords(words.split(' '))
  // const pk = bitcore.HDPrivateKey.fromSeed(m.toHex(), bitcore.Networks.linenet); // live
  const pk = bitcore.HDPrivateKey.fromSeed(m.toHex(), bitcore.Networks.testnet); // test
  const derived = pk.derive("m/0'/0/" + "0");
  // const address = new bitcore.Address(derived.publicKey, bitcore.Networks.livenet); // live
  const address = new bitcore.Address(derived.publicKey, bitcore.Networks.testnet); // test

  const wifKey = derived.privateKey.toWIF();
  const bitcoinAddress = address.toString();

  return {
    wifKey,
    bitcoinAddress,
  };
};
const getAddress = words => _parseWords(words).bitcoinAddress;
const getKey = words => _parseWords(words).wifKey;
const decodeTx = rawTx => new bitcore.Transaction(rawTx).toObject();

module.exports = {
  makeWords,
  getAddress,
  getKey,
  decodeTx,
  bitcore,
};
