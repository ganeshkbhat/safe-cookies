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

let saltKey = getRandomKey();

console.log("Initial String: ", "Testing new crypter");

let cryptedtext = encrypt((v) => { console.log(v.toString("base64")); return v; }, saltKey, 0, cryptoencrypt)("Testing new crypter");
console.log("encrypt wrapper default: ", cryptedtext.toString("base64"));

let decryptedtext = decrypt((v) => { console.log(v.toString("base64")); return v; }, saltKey, 0, cryptodecrypt)(cryptedtext);
console.log("decrypt wrapper default: ", decryptedtext.toString());

