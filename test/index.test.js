/**
 * 
 * Package: 
 * Author: Ganesh B
 * Description: 
 * Install: npm i  --save
 * Github: https://github.com/ganeshkbhat/
 * npmjs Link: https://www.npmjs.com/package/
 * File: index.js
 * File Description: 
 * 
*/

/* eslint no-console: 0 */

'use strict';

import { expect } from 'chai';
import pkg from "../index.js";
const { encrypt, decrypt, encryptRecursive, decryptRecursive, cryptoencrypt, cryptodecrypt, getKeyFromPassword, getRandomKey } = pkg;
import { hashContent, dehashContent } from "hasher-apis";

/**
 * NOTE: Always avoid nested structure to store values
 *          Higher the nesting, higher the order of errors
 *          for working or testing
 */
var testValues = {
  "test": {
    value: "testValue",
    options: { t: 10 }
  }
};

var values = {};

/**
 * testWriter
 *
 * @param {*} name
 * @param {*} value [Value is the messagetext to be encrypted and decrypted. Use the index of value as the index property's value]
 * @param {*} options
 */
function testWriter(name, value, options) {
  values[name] = {
    value: value,
    options: options
  }
  console.log("testWriter log:", name, value, options);
}

/**
 * testWriterAll
 *
 * @param {*} writerObject
 * @param {*} options
 */
function testWriterAll(writerObject, options) {
  values = {};
  values = { ...writerObject };
  console.log("testWriterAll log:", ...writerObject);
}

/**
 * testWriterUpdate
 * 
 * @param {*} name 
 * @param {*} value [Value is the messagetext to be encryptedand decrypted. Use the index of value as the index property's value]
 * @param {*} options 
 */
function testWriterUpdate(name, value, options) {
  values[name] = {
    value: value,
    options: options
  }
  console.log("testWriterUpdate log:", name, value, options);
}

/**
 * testWriterUpdateAll
 *
 * @param {*} writerObject
 * @param {*} options
 */
function testWriterUpdateAll(writerObject, options) {
  values = { ...values, ...writerObject }
  console.log("testWriterUpdateAll log:", ...writerObject);
}

/**
 * testReader
 *
 * @param {*} name
 * @return {*} 
 */
function testReader(name) {
  console.log("testReader log:", values[name].value);
  return values[name].value;
}

/**
 * testReaderAll
 *
 * @param {*} name
 * @return {*} 
 */
function testReaderAll(name) {
  console.log("testReaderAll log:",values);
  return values;
}

describe('[A] Encrypt Functions using testWriterEncrypted functions', function () {

  it('[Test A.1] tests for using encrypting functions wrapping a testWriter function', function (done) {
    let testWriterEncrypted = encrypt(testWriter, "salt", 1, hashContent);
    let t1 = "test";
    testWriterEncrypted("test", "testValue", { t: 10 });
    expect(dehashContent(values[t1].value, "salt", "aes-256-ctr", "sha256", "base64", { logger: console.log }), "test").to.equal(testValues[t1].value);
    done();
  });

});

describe('[A] Decrypt Functions wrapping a testReaderEncrypted function', function () {

  it('[Test A.2] tests for using decrypting functions wrapping a testReader function', function (done) {

    let testReaderEncrypted = decrypt(testReader, "salt", 1, dehashContent);
    let t1 = "test";
    // || dehashContent(data, salt, "aes-256-ctr", "sha256", "base64", { logger: console.log })
    values[t1].value = testReaderEncrypted(t1);
    // TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an 
    //        instance of Buffer, ArrayBuffer, or Array or an Array-like Object
    expect(values[t1].value).to.equal(testValues[t1].value);
    done();
  });

});

describe('[B] Encrypt Functions using testWriterEncrypted function and default string response', function () {

  it('[Test  B.1] tests for wrapping a testWriter function using simple string like hash response', function (done) {
    let testWriterEncrypted = encrypt(testWriter, getKeyFromPassword("password", "testsalt"), 1, cryptoencrypt);
    let t1 = "test";
    testWriterEncrypted(t1, "testValue", { t: 10 });
    expect(cryptodecrypt(values[t1].value, getKeyFromPassword("password", "testsalt")).toString()).to.equal(testValues[t1].value);
    done();
  });

});

describe('[B] Decrypt Functions wrapping a testReaderEncrypted function and default string response', function () {

  it('[Test B.2] tests for wrapping a testWriter function using simple string like hash response', function (done) {
    let testReaderEncrypted = decrypt(testReader, getKeyFromPassword("password", "testsalt"), 1, cryptodecrypt);
    let t1 = "test";
    values[t1].value = testReaderEncrypted(t1);
    // TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an 
    //        instance of Buffer, ArrayBuffer, or Array or an Array-like Object
    expect(values[t1].value.toString()).to.equal(testValues[t1].value);
    done();
  });

});

describe('[C] Encrypt Functions tests', function () {

  it('[Test  C.1] tests for cryptoencrypt - cryptodecrypt functions', function (done) {
    let k = getRandomKey();
    let t = "Testing string";
    let e = cryptoencrypt(t, k);
    let de = cryptodecrypt(e, k);
    expect(cryptodecrypt(cryptoencrypt(t, k), k).toString()).to.equal(de.toString());
    done();
  });

  it('[Test  C.2] tests for hashContent - dehashContent functions', function (done) {
    let k = "testsalt";
    let t = "Testing string";
    let e = hashContent(t, k);
    let de = dehashContent(e, k);
    expect(dehashContent(hashContent("Testing string", k), k)).to.equal(de);
    done();
  });

});

