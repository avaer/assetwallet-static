const mnemonic = require('mnemonic-browser');
const bitcore = require('./deps/bitcore-lib');
const utilBitcore = require('./deps/util.bitcore.js')

module.exports = ({random}) => {

const makeWords = () => {
  const result = Array(12);
  for (let i = 0; i < result.length; i++) {
    result[i] = mnemonic.words[Math.floor(random() * mnemonic.words.length)];
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
const signTx = (rawTx, wifKey) => new Promise((accept, reject) => {
  new utilBitcore.CWPrivateKey(wifKey).signRawTransaction(rawTx, (err, signedRawTx) => {
    if (!err) {
      accept(signedRawTx);
    } else {
      reject(err);
    }
  });
});

return {
  makeWords,
  getAddress,
  getKey,
  decodeTx,
  signTx,
  bitcore,
};

};
