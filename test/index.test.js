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
const { encrypt, decrypt, encryptRecursive, decryptRecursive } = pkg;
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

function testWriter(name, value, options) {
  values[name] = {
    value: value,
    options: options
  }
  console.log(name, value, options);
}

function testWriterAll(writerObject, options) {
  values = {};
  values = { ...writerObject };
  console.log(...writerObject);
}

function testWriterUpdate(name, value, options) {
  values[name] = {
    value: value,
    options: options
  }
  console.log(name, value, options);
}

function testWriterUpdateAll(writerObject, options) {
  values = { ...values, ...writerObject }
  console.log(...writerObject);
}

function testReader(name) {
  console.log(values[name].value);
  return values[name].value;
}

function testReaderAll(name) {
  console.log(values);
  return values;
}

describe('Encrypt Functions', function () {

  it('[Test A] tests for wrapping a testWriter function', function (done) {
    let testWriterEncrypted = encrypt(testWriter, "salt");
    let t1 = "test";
    testWriterEncrypted("test", "testValue", { t: 10 });
    expect(dehashContent(values[t1].value, "salt", "aes-256-ctr", "sha256", "base64", { logger: console.log }), "test").to.equal(testValues[t1].value);
    done();
  });

});

describe('Decrypt Functions wrapping a testReader function', function () {

  it('[Test A] tests for ', function (done) {

    let testReaderEncrypted = decrypt(testReader, "salt");
    let t1 = "test";
    values[t1].value = testReaderEncrypted(t1);
    // TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an 
    //        instance of Buffer, ArrayBuffer, or Array or an Array-like Object
    expect(values[t1].value).to.equal(testValues[t1].value);
    done();
  });

});

// describe('Encrypt Functions Recursively', function () {

//   it('[Test A] tests for recursive encrypter functions', function (done) {
//     let testWriterEncrypted = encryptRecursive(testWriterAll, "salt");
//     let t1 = "test";
//     values = {};

//     testWriterEncrypted({
//       "test": {
//         value: "testValue",
//         options: { t: 10 }
//       }
//     })

//     expect(dehashContent(values[t1].value, "salt", "aes-256-ctr", "sha256", "base64", { logger: console.log }), "test").to.equal(testValues[t1]);
//     done();
//   });

// });

// describe('Decrypt Functions Recursively', function () {

//   it('[Test A] tests for recursive decrypter functions', function (done) {
//     let testReaderEncrypted = decryptRecursive(testReaderAll, "salt");
//     let t1 = "test";

//     expect(values[t1]).to.equal(testValues[t1]);
//     done();
//   });

// });

// describe('Encrypt Functions Recursively', function () {
//
//   it('[Test A] tests for ', function (done) {
//     expect(values[t1]).to.equal(testValues[t1]);
//     done();
//   });
//
// });

// describe('Decrypt Functions Recursively', function () {
//
//   it('[Test A] tests for ', function (done) {
//     expect(values[t1]).to.equal(testValues[t1]);
//     done();
//   });
//
// });
