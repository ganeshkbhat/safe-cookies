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

import pkg from "../index.js";
const { encrypt, decrypt, encryptRecursive, decryptRecursive, cryptoencrypt, cryptodecrypt, getKeyFromPassword, getRandomKey } = pkg;
let saltKey = getRandomKey();

console.log("Initial String: ", "Testing new crypter");

let cryptedtext = encrypt((v) => { console.log(v.toString("base64")); return v; }, saltKey, 0, cryptoencrypt)("Testing new crypter");
console.log("encrypt wrapper default: ", cryptedtext.toString("base64"));

let decryptedtext = decrypt((v) => { console.log(v.toString("base64")); return v; }, saltKey, 0, cryptodecrypt)(cryptedtext);
console.log("decrypt wrapper default: ", decryptedtext.toString());

