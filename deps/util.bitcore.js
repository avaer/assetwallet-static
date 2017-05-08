// XXX util.bitcore.js

var bitcore = require('./bitcore-lib')
var async = require('async');

// this 'global' is overwritten by tests!
const USE_TESTNET = true;
var NETWORK = USE_TESTNET ? bitcore.Networks.testnet : bitcore.Networks.livenet;

// priv: private key wif or hex
var CWPrivateKey = function(priv) {
  this.priv = null;
  this.init(priv);
}

CWPrivateKey.prototype.init = function(priv) {
  try {
    if (typeof priv === "string") {
      priv = bitcore.PrivateKey(priv, NETWORK);
    }
    this.priv = priv;
  } catch (err) {
    this.priv = null;
  }
}

CWPrivateKey.prototype.getAddress = function() {
  return this.priv.toAddress(NETWORK).toString();
}

CWPrivateKey.prototype.getAltAddress = function() {
  var tmpPriv = this.priv.toObject();
  tmpPriv.compressed = !tmpPriv.compressed;

  return bitcore.PrivateKey(tmpPriv).toAddress(NETWORK).toString();
}

CWPrivateKey.prototype.getAddresses = function() {
  return [
    this.getAddress(),
    this.getAltAddress()
  ];
}

CWPrivateKey.prototype.isValid = function() {
  try {
    return bitcore.Address.isValid(this.getAddress(), NETWORK, bitcore.Address.Pay2PubKeyHash);
  } catch (err) {
    return false;
  }
}

CWPrivateKey.prototype.getPub = function() {
  try {
    return this.priv.toPublicKey().toString();
  } catch (err) {
    return false;
  }
}

/**
 * @param {string} message
 * @param {string} format    hex, base64
 * @returns {*}
 */
CWPrivateKey.prototype.signMessage = function(message, format) {
  var base64 = bitcore.Message(message).sign(this.priv); // always returns base64 string
  return bitcore.deps.Buffer(base64, 'base64').toString(format || 'base64');
}

CWPrivateKey.prototype.signRawTransaction = function(unsignedHex, disableIsFullySigned, cb) {
  if (typeof disableIsFullySigned === "function") {
    cb = disableIsFullySigned;
    disableIsFullySigned = null;
  }
  checkArgType(cb, "function");

  try {
    CWBitcore.signRawTransaction(unsignedHex, this, disableIsFullySigned, cb);
  } catch (err) {
    // async.nextTick to avoid parent trycatch
    async.nextTick(function() {
      cb(err);
    });
  }
}

CWPrivateKey.prototype.checkTransactionDest = function(txHex, destAdress) {
  checkArgsType(arguments, ["string", "object"]);
  try {
    return CWBitcore.checkTransactionDest(txHex, this.getAddresses(), destAdress);
  } catch (err) {
    return false;
  }
}

CWPrivateKey.prototype.checkAndSignRawTransaction = function(unsignedHex, destAdress, disableIsFullySigned, cb) {
  if (typeof(destAdress) == 'string') {
    destAdress = [destAdress];
  }
  if (typeof disableIsFullySigned === "function") {
    cb = disableIsFullySigned;
    disableIsFullySigned = null;
  }
  checkArgType(cb, "function");

  try {
    if (this.checkTransactionDest(unsignedHex, destAdress)) {
      this.signRawTransaction(unsignedHex, disableIsFullySigned, cb);
    } else {
      throw new Error("Failed to validate transaction destination");
    }
  } catch (err) {
    // async.nextTick to avoid parent trycatch
    async.nextTick(function() {
      cb(err);
    });
  }
}

CWPrivateKey.prototype.getWIF = function() {
  return this.priv.toWIF();
}

CWPrivateKey.prototype.encrypt = function(message) {
  return CWBitcore.encrypt(message, this.priv.toString());
}

CWPrivateKey.prototype.decrypt = function(cryptedMessage) {
  return CWBitcore.decrypt(cryptedMessage, this.priv.toString());
}

// TODO: rename to be more generic
var CWBitcore = {}

/**
 *
 * @param {bitcore.Script} script
 * @returns {boolean}
 */
CWBitcore.isOutScript = function(script) {
  return script.isPublicKeyOut() ||
    script.isPublicKeyHashOut() ||
    script.isMultisigOut() ||
    script.isScriptHashOut() ||
    script.isDataOut();
}

CWBitcore.isValidAddress = function(val) {
  try {
    return bitcore.Address.isValid(val, NETWORK, bitcore.Address.Pay2PubKeyHash);
  } catch (err) {
    return false;
  }
}

CWBitcore.isValidMultisigAddress = function(val) {
  try {
    var addresses = val.split("_");
    if (addresses.length != 4 && addresses.length != 5) {
      return false;
    }
    var required = parseInt(addresses.shift());
    var provided = parseInt(addresses.pop());
    if (isNaN(required) || isNaN(provided) || provided != addresses.length || required > provided || required < 1) {
      return false;
    }
    for (var a = 0; a < addresses.length; a++) {
      if (!CWBitcore.isValidAddress(addresses[a])) {
        return false;
      }
    }
    return true;
  } catch (err) {
    return false;
  }
}

CWBitcore.MultisigAddressToAddresses = function(val) {

  if (CWBitcore.isValidAddress(val)) {
    return [val];
  } else if (CWBitcore.isValidMultisigAddress(val)) {
    var addresses = val.split("_");
    addresses.shift();
    addresses.pop();

    return addresses;
  } else {
    return [];
  }
}

CWBitcore.genKeyMap = function(cwPrivateKeys) {
  var wkMap = {};
  cwPrivateKeys.forEach(function(cwPrivateKey) {
    wkMap[cwPrivateKey.getAddress()] = cwPrivateKey.priv;
  });

  return wkMap;
}

/**
 *
 * @param {string} unsignedHex
 * @param {CWPrivateKey} cwPrivateKey
 * @param {boolean|function} [disableIsFullySigned]
 * @param {function} cb
 * @returns {*}
 */
CWBitcore.signRawTransaction = function(unsignedHex, cwPrivateKey, disableIsFullySigned, cb) {
  // make disableIsFullySigned optional
  if (typeof disableIsFullySigned === "function") {
    cb = disableIsFullySigned;
    disableIsFullySigned = null;
  }
  checkArgType(unsignedHex, "string");
  checkArgType(cwPrivateKey, "object");
  checkArgType(cb, "function");

  try {
    var tx = bitcore.Transaction(unsignedHex);

    var keyMap = CWBitcore.genKeyMap([cwPrivateKey]);
    var keyChain = [];

    async.forEachOf(
      tx.inputs,
      function(input, idx, cb) {
        (function(cb) {
          var inputObj;

          // dissect what was set as input script to use it as output script
          var script = bitcore.Script(input._scriptBuffer.toString('hex'));
          var multiSigInfo;
          var addresses = [];

          switch (script.classify()) {
            case bitcore.Script.types.PUBKEY_OUT:
              inputObj = input.toObject();
              inputObj.output = bitcore.Transaction.Output({
                script: input._scriptBuffer.toString('hex'),
                satoshis: 0 // we don't know this value, setting 0 because otherwise it's going to cry about not being an INT
              });
              tx.inputs[idx] = new bitcore.Transaction.Input.PublicKey(inputObj);

              addresses = [script.toAddress(NETWORK).toString()];

              return cb(null, addresses);

            case bitcore.Script.types.PUBKEYHASH_OUT:
              inputObj = input.toObject();
              inputObj.output = bitcore.Transaction.Output({
                script: input._scriptBuffer.toString('hex'),
                satoshis: 0 // we don't know this value, setting 0 because otherwise it's going to cry about not being an INT
              });
              tx.inputs[idx] = new bitcore.Transaction.Input.PublicKeyHash(inputObj);

              addresses = [script.toAddress(NETWORK).toString()];

              return cb(null, addresses);

            case bitcore.Script.types.MULTISIG_IN:
              inputObj = input.toObject();

              return failoverAPI(
                'get_script_pub_key',
                {tx_hash: inputObj.prevTxId, vout_index: inputObj.outputIndex},
                function(data) {
                  inputObj.output = bitcore.Transaction.Output({
                    script: data['scriptPubKey']['hex'],
                    satoshis: bitcore.Unit.fromBTC(data['value']).toSatoshis()
                  });

                  multiSigInfo = CWBitcore.extractMultiSigInfoFromScript(inputObj.output.script);

                  inputObj.signatures = bitcore.Transaction.Input.MultiSig.normalizeSignatures(
                    tx,
                    new bitcore.Transaction.Input.MultiSig(inputObj, multiSigInfo.publicKeys, multiSigInfo.threshold),
                    idx,
                    script.chunks.slice(1, script.chunks.length).map(function(s) { return s.buf; }),
                    multiSigInfo.publicKeys
                  );

                  tx.inputs[idx] = new bitcore.Transaction.Input.MultiSig(inputObj, multiSigInfo.publicKeys, multiSigInfo.threshold);

                  addresses = CWBitcore.extractMultiSigAddressesFromScript(inputObj.output.script);

                  return cb(null, addresses);
                }
              );

            case bitcore.Script.types.MULTISIG_OUT:
              inputObj = input.toObject();
              inputObj.output = bitcore.Transaction.Output({
                script: input._scriptBuffer.toString('hex'),
                satoshis: 0 // we don't know this value, setting 0 because otherwise it's going to cry about not being an INT
              });

              multiSigInfo = CWBitcore.extractMultiSigInfoFromScript(inputObj.output.script);
              tx.inputs[idx] = new bitcore.Transaction.Input.MultiSig(inputObj, multiSigInfo.publicKeys, multiSigInfo.threshold);

              addresses = CWBitcore.extractMultiSigAddressesFromScript(inputObj.output.script);

              return cb(null, addresses);

            case bitcore.Script.types.SCRIPTHASH_OUT:
              // signing scripthash not supported, just skipping it, something external will have to deal with it
              return cb();

            case bitcore.Script.types.DATA_OUT:
            case bitcore.Script.types.PUBKEY_IN:
            case bitcore.Script.types.PUBKEYHASH_IN:
            case bitcore.Script.types.SCRIPTHASH_IN:
              // these are 'done', no reason to touch them!
              return cb();

            default:
              return cb(new Error("Unknown scriptPubKey [" + script.classify() + "](" + script.toASM() + ")"));
          }

        })(function(err, addresses) {
          if (err) {
            return cb(err);
          }

          // NULL means it isn't neccesary to sign it
          if (addresses === null) {
            return cb();
          }

          // unique filter
          addresses = addresses.filter(function(address, idx, self) {
            return address && self.indexOf(address) === idx;
          });

          var _keyChain = addresses.map(function(address) {
            return typeof keyMap[address] !== "undefined" ? keyMap[address] : null;
          }).filter(function(key) {
            return !!key
          });

          if (_keyChain.length === 0) {
            throw new Error("Missing private key to sign input: " + idx);
          }

          keyChain = keyChain.concat(_keyChain);

          cb();
        });
      },
      function(err) {
        if (err) {
          // async.nextTick to avoid parent trycatch
          return async.nextTick(function() {
            cb(err);
          });
        }

        // unique filter
        keyChain = keyChain.filter(function(key, idx, self) {
          return key && self.indexOf(key) === idx;
        });

        // sign with each key
        keyChain.forEach(function(priv) {
          tx.sign(priv);
        });

        // disable any checks that have anything to do with the values, because we don't know the values of the inputs
        var opts = {
          disableIsFullySigned: disableIsFullySigned,
          disableSmallFees: true,
          disableLargeFees: true,
          disableDustOutputs: true,
          disableMoreOutputThanInput: true
        };

        // async.nextTick to avoid parent trycatch
        async.nextTick(function() {
          cb(null, tx.serialize(opts));
        });
      }
    );
  } catch (err) {
    // async.nextTick to avoid parent trycatch
    async.nextTick(function() {
      cb(err);
    });
  }
};

CWBitcore.extractMultiSigAddressesFromScript = function(script) {
  checkArgType(script, "object");

  if (!script.isMultisigOut()) {
    return [];
  }

  var nKeysCount = bitcore.Opcode(script.chunks[script.chunks.length - 2].opcodenum).toNumber() - bitcore.Opcode.map.OP_1 + 1;
  var pubKeys = script.chunks.slice(script.chunks.length - 2 - nKeysCount, script.chunks.length - 2);

  return pubKeys.map(function(pubKey) {
    // using custom code to pubKey->address instead of PublicKey.fromDER because pubKey isn't valid DER
    return bitcore.Address(bitcore.crypto.Hash.sha256ripemd160(pubKey.buf), NETWORK, bitcore.Address.PayToPublicKeyHash).toString();
    // return bitcore.Address.fromPublicKey(bitcore.PublicKey.fromDER(pubKey.buf, /* strict= */false)).toString();
  });
};

CWBitcore.extractMultiSigInfoFromScript = function(script) {
  checkArgType(script, "object");

  if (!script.isMultisigOut()) {
    return [];
  }

  var nKeysCount = bitcore.Opcode(script.chunks[script.chunks.length - 2].opcodenum).toNumber() - bitcore.Opcode.map.OP_1 + 1;
  var threshold = bitcore.Opcode(script.chunks[script.chunks.length - nKeysCount - 2 - 1].opcodenum).toNumber() - bitcore.Opcode.map.OP_1 + 1;
  return {
    publicKeys: script.chunks.slice(script.chunks.length - 2 - nKeysCount, script.chunks.length - 2).map(function(pubKey) {
      return bitcore.PublicKey(pubKey.buf);
    }),
    threshold: threshold
  };
};

/**
 * @param {bitcore.Transaction.Output} output
 * @returns {string} either address or list of addresses (as CSV) or "" for op_return
 */
CWBitcore.extractAddressFromTxOut = function(output) {
  checkArgType(output, "object");

  switch (output.script.classify()) {
    case bitcore.Script.types.PUBKEY_OUT:
      return output.script.toAddress(NETWORK).toString();

    case bitcore.Script.types.PUBKEYHASH_OUT:
      return output.script.toAddress(NETWORK).toString();

    case bitcore.Script.types.SCRIPTHASH_OUT:
      return output.script.toAddress(NETWORK).toString();

    case bitcore.Script.types.MULTISIG_OUT:
      var addresses = CWBitcore.extractMultiSigAddressesFromScript(output.script);
      return addresses.join(",");

    case bitcore.Script.types.DATA_OUT:
      return "";

    default:
      throw new Error("Unknown type [" + output.script.classify() + "]");
  }
}

/**
 * @param {string} source
 * @param {string} txHex
 * @returns {*}
 */
CWBitcore.extractChangeTxoutValue = function(source, txHex) {
  checkArgsType(arguments, ["string", "string"]);

  var tx = bitcore.Transaction(txHex);

  return tx.outputs.map(function(output, idx) {
    var address = CWBitcore.extractAddressFromTxOut(output);

    if (address && address == source) {
      return output.satoshis;
    }

    return 0;
  }).reduce(function(value, change) { return change + value; });
}

/**
 * @TODO: check the pubkey instead
 *
 * @param {string}    txHex
 * @param {string[]}  source  list of compressed and uncompressed addresses
 * @param {string[]}  dest
 * @returns {boolean}
 */
CWBitcore.checkTransactionDest = function(txHex, source, dest) {
  checkArgsType(arguments, ["string", "object", "object"]);

  source = [].concat.apply([], source.map(function(source) {
    return CWBitcore.MultisigAddressToAddresses(source);
  }));
  dest = [].concat.apply([], dest.map(function(dest) {
    return CWBitcore.MultisigAddressToAddresses(dest);
  }));

  var tx = bitcore.Transaction(txHex);

  var outputsValid = tx.outputs.map(function(output, idx) {
    var address = null;

    switch (output.script.classify()) {
      case bitcore.Script.types.PUBKEY_OUT:
        address = output.script.toAddress(NETWORK).toString();
        break;

      case bitcore.Script.types.PUBKEYHASH_OUT:
        address = output.script.toAddress(NETWORK).toString();
        break;

      case bitcore.Script.types.SCRIPTHASH_OUT:
        address = output.script.toAddress(NETWORK).toString();
        break;

      case bitcore.Script.types.MULTISIG_OUT:
        var addresses = CWBitcore.extractMultiSigAddressesFromScript(output.script);

        var isSource = dest.sort().join() == addresses.sort().join();
        var isDest = source.sort().join() == addresses.sort().join();

        // if multisig we only accept it if it's value indicates it's a data output (<= MULTISIG_DUST_SIZE or <= REGULAR_DUST_SIZE*2)
        //  or a perfect match with the dest or source (change)
        return output.satoshis <= Math.max(MULTISIG_DUST_SIZE, REGULAR_DUST_SIZE * 2) || isSource || isDest;

      case bitcore.Script.types.DATA_OUT:
        return true;

      default:
        throw new Error("Unknown type [" + output.script.classify() + "]");
    }

    var containsSource = _.intersection([address], source).length > 0;
    var containsDest = _.intersection([address], dest).length > 0;

    return containsDest || containsSource;
  });

  return outputsValid.filter(function(v) { return !v; }).length === 0;
}

CWBitcore.compareOutputs = function(source, txHexs) {
  var t;

  if (txHexs[0].indexOf("=====TXSIGCOLLECT") != -1) {
    // armory transaction, we just compare if strings are the same.
    for (t = 1; t < txHexs.length; t++) {
      if (txHexs[t] != txHexs[0]) {
        return false;
      }
    }

    return true;
  } else {
    var tx0 = bitcore.Transaction(txHexs[0]);

    var txHexesValid = txHexs.map(function(txHex, idx) {
      if (idx === 0) {
        return true;
      }

      var tx1 = bitcore.Transaction(txHex);

      if (tx0.outputs.length != tx1.outputs.length) {
        return false;
      }

      var outputsValid = tx0.outputs.map(function(output, idx) {
        var addresses0 = CWBitcore.extractAddressFromTxOut(output).split(',').sort().join(',');
        var addresses1 = CWBitcore.extractAddressFromTxOut(tx1.outputs[idx]).split(',').sort().join(',');
        var amount0 = output.satoshis;
        var amount1 = tx1.outputs[idx].satoshis;

        // addresses need to be the same and values need to be the same
        //  expect for the change output
        return addresses0 == addresses1 && (amount0 == amount1 || addresses0.indexOf(source) != -1);
      });

      return outputsValid.filter(function(v) { return !v; }).length === 0;
    })

    return txHexesValid.filter(function(v) { return !v; }).length === 0;
  }
}

CWBitcore.pubKeyToPubKeyHash = function(pubKey) {
  return bitcore.Address.fromPublicKey(bitcore.PublicKey(pubKey, {network: NETWORK}), NETWORK).toString();
}

CWBitcore.encrypt = function(message, password) {
  return CryptoJS.AES.encrypt(message, password).toString();
}

CWBitcore.decrypt = function(cryptedMessage, password) {
  return CryptoJS.enc.Utf8.stringify(CryptoJS.AES.decrypt(cryptedMessage, password));
}

CWBitcore.getQuickUrl = function(passphrase, password) {
  var url = location.protocol + '//' + location.hostname + '/#cp=';
  url += CWBitcore.encrypt(passphrase, password);
  return url;
}

// XXX util.generic.js

function assert(condition, message) {
  if (!condition) throw message || "Assertion failed";
}

function checkArgType(arg, type) {
  assert((typeof arg).toLowerCase() == type.toLowerCase(), "Invalid argument type");
}

function checkArgsType(args, types) {
  for (var a = 0; a < args.length; a++) {
    checkArgType(args[a], types[a]);
  }
}

function numberWithCommas(x) {
  //print a number with commas, as appropriate (http://stackoverflow.com/a/2901298)
  if (!isNumber(x)) return x;
  var parts = x.toString().split(".");
  parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return parts.join(".");
}

function isNumber(n) {
  //http://stackoverflow.com/a/1830844
  return !isNaN(parseFloat(n)) && isFinite(n);
}

function numberHasDecimalPlace(n) {
  return n % 1 != 0;
}

function byteCount(s) {
  /*http://stackoverflow.com/a/12203648*/
  return encodeURI(s).split(/%..|./).length - 1;
}

function randomIntFromInterval(min, max) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

function selectText(element) {
  var doc = document
    , text = doc.getElementById(element)
    , range, selection
    ;
  if (doc.body.createTextRange) { //ms
    range = doc.body.createTextRange();
    range.moveToElementText(text);
    range.select();
  } else if (window.getSelection) { //all others
    selection = window.getSelection();
    range = doc.createRange();
    range.selectNodeContents(text);
    selection.removeAllRanges();
    selection.addRange(range);
  }
}

function noExponents(n) {
  /* avoids floats resorting to scientific notation
   * adopted from: http://stackoverflow.com/a/16116500
   */
  var data = String(n).split(/[eE]/);
  if (data.length == 1) return data[0];

  var z = '', sign = this < 0 ? '-' : '',
    str = data[0].replace('.', ''),
    mag = Number(data[1]) + 1;

  if (mag < 0) {
    z = sign + '0.';
    while (mag++) z += '0';
    return z + str.replace(/^\-/, '');
  }
  mag -= str.length;
  while (mag--) z += '0';
  return str + z;
}

//Dynamic array sort, allows for things like: People.sortBy("Name", "-Surname");
//Won't work below IE9, but totally safe otherwise
//From http://stackoverflow.com/a/4760279 
!function() {
  function _dynamicSortMultiple(attr) {
    var props = arguments;
    return function(obj1, obj2) {
      var i = 0, result = 0, numberOfProperties = props.length;
      /* try getting a different result from 0 (equal)
       * as long as we have extra properties to compare
       */
      while (result === 0 && i < numberOfProperties) {
        result = _dynamicSort(props[i])(obj1, obj2);
        i++;
      }
      return result;
    }
  }

  function _dynamicSort(property) {
    var sortOrder = 1;
    if (property[0] === "-") {
      sortOrder = -1;
      property = property.substr(1);
    }
    return function(a, b) {
      var result = (a[property] < b[property]) ? -1 : (a[property] > b[property]) ? 1 : 0;
      return result * sortOrder;
    }
  }

  Object.defineProperty(Array.prototype, "sortBy", {
    enumerable: false,
    writable: true,
    value: function() {
      return this.sort(_dynamicSortMultiple.apply(null, arguments));
    }
  });
}();

//Object comparison -- From http://stackoverflow.com/a/1144249
function deepCompare() {
  var leftChain, rightChain;

  function compare2Objects(x, y) {
    var p;

    // remember that NaN === NaN returns false
    // and isNaN(undefined) returns true
    if (isNaN(x) && isNaN(y) && typeof x === 'number' && typeof y === 'number') {
      return true;
    }

    // Compare primitives and functions.     
    // Check if both arguments link to the same object.
    // Especially useful on step when comparing prototypes
    if (x === y) {
      return true;
    }

    // Works in case when functions are created in constructor.
    // Comparing dates is a common scenario. Another built-ins?
    // We can even handle functions passed across iframes
    if ((typeof x === 'function' && typeof y === 'function') ||
      (x instanceof Date && y instanceof Date) ||
      (x instanceof RegExp && y instanceof RegExp) ||
      (x instanceof String && y instanceof String) ||
      (x instanceof Number && y instanceof Number)) {
      return x.toString() === y.toString();
    }
    // At last checking prototypes as good a we can
    if (!(x instanceof Object && y instanceof Object)) {
      return false;
    }
    if (x.isPrototypeOf(y) || y.isPrototypeOf(x)) {
      return false;
    }
    if (x.constructor !== y.constructor) {
      return false;
    }
    if (x.prototype !== y.prototype) {
      return false;
    }
    // check for infinitive linking loops
    if (leftChain.indexOf(x) > -1 || rightChain.indexOf(y) > -1) {
      return false;
    }

    // Quick checking of one object beeing a subset of another.
    // todo: cache the structure of arguments[0] for performance
    for (p in y) {
      if (y.hasOwnProperty(p) !== x.hasOwnProperty(p)) {
        return false;
      }
      else if (typeof y[p] !== typeof x[p]) {
        return false;
      }
    }
    for (p in x) {
      if (y.hasOwnProperty(p) !== x.hasOwnProperty(p)) {
        return false;
      }
      else if (typeof y[p] !== typeof x[p]) {
        return false;
      }
      switch (typeof (x[p])) {
        case 'object':
        case 'function':

          leftChain.push(x);
          rightChain.push(y);

          if (!compare2Objects(x[p], y[p])) {
            return false;
          }

          leftChain.pop();
          rightChain.pop();
          break;

        default:
          if (x[p] !== y[p]) {
            return false;
          }
          break;
      }
    }
    return true;
  }

  if (arguments.length < 1) {
    return true; //Die silently? Don't know how to handle such case, please help...
    // throw "Need two or more arguments to compare";
  }
  for (var i = 1, l = arguments.length; i < l; i++) {

    leftChain = []; //todo: this can be cached
    rightChain = [];

    if (!compare2Objects(arguments[0], arguments[i])) {
      return false;
    }
  }
  return true;
}

function timestampToString(timestamp) {
  return moment(timestamp * 1000).format("MMM Do YYYY, h:mm:ss a");
}

function satoshiToPercent(value) {
  var percent = mulFloat(divFloat(value, UNIT), 100);
  return smartFormat(percent, 4, 4) + '%'
}

function currency(amount, unit) {
  return smartFormat(normalizeQuantity(amount), 4, 4) + ' ' + unit;
}

function satoshiToXCP(amount) {
  return currency(amount, 'XCP');
}

function round(amount, decimals) {
  if (decimals === undefined || decimals === null) decimals = 8;
  return Decimal.round(new Decimal(amount), decimals, Decimal.MidpointRounding.ToEven).toFloat();
}

// Reduce a fraction by finding the Greatest Common Divisor and dividing by it.
function reduce(numerator, denominator) {
  var gcd = function gcd(a, b) {
    return b ? gcd(b, a % b) : a;
  };
  gcd = gcd(numerator, denominator);
  return [numerator / gcd, denominator / gcd];
}

function isValidURL(str) {
  var pattern = /^(https?:\/\/)?((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,}|((\d{1,3}\.){3}\d{1,3}))(\:\d+)?(\/[-a-z\d%_.~+]*)*(\?[;&a-z\d%_.~+=-]*)?(\#[-a-z\d_]*)?$/i;

  if (!str.match(pattern)) {
    return false;
  } else {
    return true;
  }
}

function get_duration(interval) {
  var interval_array = interval.split('/');
  for (var i in interval_array) {
    if (interval_array[i].substring(0, 1) == 'P') {
      var duration = nezasa.iso8601.Period.parseToString(interval_array[i]);
      return duration;
    }
  }
  return 'Unknown';
}

var bytesToHex = function(t) {
  for (var e = [], r = 0; r < t.length; r++)e.push((t[r] >>> 4).toString(16)), e.push((15 & t[r]).toString(16));
  return e.join("")
};
var hexToBytes = function(t) {
  for (var e = [], r = 0; r < t.length; r += 2)e.push(parseInt(t.substr(r, 2), 16));
  return e
};

function genRandom() {
  var random = new Uint8Array(16);

  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(random); // Catch no entropy here.
  } else if (window.msCrypto && window.msCrypto.getRandomValues) {
    window.msCrypto.getRandomValues(random);
  } else {
    var errText = "Your browser lacks a way to securely generate random values. Please use a different, newer browser.";
    bootbox.alert(errText);
    assert(false, errText);
  }

  return bytesToHex(random);
}

function doubleHash(hexstr) {
  return bitcore.util.sha256(bitcore.util.sha256(hexToBytes(hexstr))).toString('hex');
}

module.exports = {
  CWPrivateKey,
};
