/**
 * 
 * Package: safecookie
 * Author: Ganesh B
 * Description: 
 * Install: npm i safecookie --save
 * Github: https://github.com/ganeshkbhat/
 * npmjs Link: https://www.npmjs.com/package/
 * File: demos/encrypt.js
 * File Description: 
 * 
*/

/* eslint no-console: 0 */

'use strict';

const pkg = require("../index.js");
const encrypt = pkg.encrypt;
const decrypt = pkg.decrypt;
const encryptRecursive = pkg.encryptRecursive;
const decryptRecursive = pkg.decryptRecursive;
const cryptoencrypt = pkg.cryptoencrypt;
const cryptodecrypt = pkg.cryptodecrypt;
const getKeyFromPassword = pkg.getKeyFromPassword;
const getRandomKey = pkg.getRandomKey;
const hashContent = require("hasher-apis").hashContent;
const dehashContent = require("hasher-apis").dehashContent;

console.log("Initial String: ", "Testing new crypter");

let cryptedtext = encrypt((v) => { console.log(v); return v; }, "testsalt", 0, hashContent)("Testing new crypter");
console.log("encrypt wrapper hashContent hasher-apis: ", cryptedtext);

let decryptedtext = decrypt((v) => { console.log(v); return v; }, "testsalt", 0, dehashContent)(cryptedtext);
console.log("decrypt wrapper dehashContent hasher-apis: ", decryptedtext);

