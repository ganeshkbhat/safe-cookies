/**
 * 
 * Package: safecookie
 * Author: Ganesh B
 * Description: 
 * Install: npm i safecookie --save
 * Github: https://github.com/ganeshkbhat/
 * npmjs Link: https://www.npmjs.com/package/
 * File: demos/decrypt.js
 * File Description: 
 * 
*/

/* eslint no-console: 0 */

'use strict';

import pkg from "../index.js";
const { encrypt, decrypt, encryptRecursive, decryptRecursive, cryptoencrypt, cryptodecrypt } = pkg;
import { hashContent, dehashContent } from "hasher-apis";

console.log("Initial String: ", "Testing new crypter");

let cryptedtext = hashContent("Testing new crypter", "testsalt");
console.log("hashContent: ", cryptedtext);

let decryptedtext = dehashContent(cryptedtext, "testsalt");
console.log("dehashContent: ", decryptedtext);




