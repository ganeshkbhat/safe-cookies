/**
 * 
 * Package: safecookie
 * Author: Ganesh B
 * Description: 
 * Install: npm i safecookie --save
 * Github: https://github.com/ganeshkbhat/
 * npmjs Link: https://www.npmjs.com/package/
 * File: test/index.cookie.test.js
 * File Description: 
 * 
*/

/* eslint no-console: 0 */

'use strict';

const expect = require('chai').expect;
const pkg = require("../index.js");
const encrypt = pkg.encrypt;
const decrypt = pkg.decrypt;
const encryptRecursive = pkg.encryptRecursive;
const decryptRecursive = pkg.decryptRecursive;
const cryptoencrypt = pkg.cryptoencrypt;
const cryptodecrypt = pkg.cryptodecrypt;
const getKeyFromPassword = pkg.getKeyFromPassword;
const getRandomKey = pkg.getRandomKey;

// const { encrypt, decrypt, encryptRecursive, decryptRecursive, cryptoencrypt, cryptodecrypt, getKeyFromPassword, getRandomKey } = pkg;
const hashContent = require("hasher-apis").hashContent;
const dehashContent = require("hasher-apis").dehashContent;

var testCookieValues = {};
var testEncryptCookieValues = {};
var cookieValues = {};


