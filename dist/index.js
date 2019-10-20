"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _elliptic = _interopRequireDefault(require("elliptic"));

var _crypto = _interopRequireDefault(require("crypto"));

var ec = new _elliptic["default"].ec('secp256k1');
/**
 * Hashes data
 * @param data {string | Buffer} data to be hashed can be string or binary
 * @param encoding {"utf8" | undefined} basically if you pass string it`s utf8, binary by default
 * @returns {string} hashed value
 */

function hash(data, encoding) {
  return crypto.createHash('sha256').update(data, encoding).digest().toString('hex');
}
/**
 * Generates ECDH key pair
 * @returns {object}
 */


function generateECDHKeyPair() {
  return ec.genKeyPair();
}
/**
 * Creates shared key from private and public keys
 * @param privateKey1 {object} alice`s private key
 * @param publicKey2 {object} bob`s public key
 * @returns {string} shared key
 */


function getECDHSharedKey(privateKey1, publicKey2) {
  return privateKey1.derive(publicKey2).toString(16);
}
/**
 * Convert hex public key to object
 * @param hexData {string} hex string of public key
 * @returns {object} public key object
 */


function getECDHPublicKeyFromHex(hexData) {
  return ec.keyFromPublic(hexData, 'hex');
}
/**
 * Convert hex private key to object
 * @param hexData {string} hex string of private key
 * @returns {object} private key object
 */


function getECDHPrivateKeyFromHex(hexData) {
  return ec.keyFromPrivate(hexData, 'hex');
}
/**
 * Create a signature
 * @param data {any} data to be signed
 * @param key {object} key with which to sign
 * @returns {string} signature
 */


function signECDH(data, key) {
  return key.sign(data).toHex();
}
/**
 * Verify signature
 * @param data {any}
 * @param signature {string}
 * @param key {object}
 * @returns {Boolean} result of verification
 */


function verifyECDHSign(data, signature, key) {
  return key.verify(data, signature);
}
/**
 * Cipher data with key
 * @param data {Buffer}
 * @param key {string}
 * @returns {Buffer}
 */


function cipher(data, key) {
  var cipher = crypto.createCipher('aes-192-cbc', key);
  cipher.update(data);
  return cipher["final"]();
}
/**
 * Decipher data with key
 * @param data {Buffer}
 * @param key {string}
 * @returns {Buffer}
 */


function decipher(data, key) {
  var decipher = crypto.createDecipher('aes-192-cbc', key);
  decipher.update(data);
  return decipher["final"]();
}

var _default = {
  hash: hash,
  generateECDHKeyPair: generateECDHKeyPair,
  getECDHSharedKey: getECDHSharedKey,
  getECDHPublicKeyFromHex: getECDHPublicKeyFromHex,
  getECDHPrivateKeyFromHex: getECDHPrivateKeyFromHex,
  signECDH: signECDH,
  verifyECDHSign: verifyECDHSign,
  cipher: cipher,
  decipher: decipher
};
exports["default"] = _default;