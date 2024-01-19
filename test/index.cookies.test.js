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

import { expect } from 'chai';
import { encrypt, decrypt, encryptRecursive, decryptRecursive } from "../index.js";

var testCookieValues = {};
var testEncryptCookieValues = {};
var cookieValues = {};


