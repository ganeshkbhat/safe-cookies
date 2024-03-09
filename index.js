/**
 * 
 * Package: safecookie
 * Author: Ganesh B
 * Description: 
 * Install: npm i safecookie --save
 * Github: https://github.com/ganeshkbhat/
 * npmjs Link: https://www.npmjs.com/package/
 * File: index.js
 * File Description: 
 * 
 * https://github.com/vibornoff/webcrypto-shim/blob/master/webcrypto-shim.js
 * 
 * 
*/

/* eslint no-console: 0 */

'use strict';


// Refs: https://github.com/auth0/auth0-spa-js/issues/113

/**
 * isBrowser
 *
 * @return {*} 
 */
function isBrowser() {
  if (typeof process === "object" && typeof require === "function") {
    return false;
  }
  if (typeof importScripts === "function") { return false; }
  if (typeof window === "object") { return true; }
}

var crypto;

if (!isBrowser()) { crypto = require("crypto"); } else { crypto = window.crypto; }

/** https://github.com/nodejs/undici/blob/main/lib/cookies/util.js */

// https://wicg.github.io/cookie-store/#cookie-maximum-attribute-value-size
const maxAttributeValueSize = 1024

// https://wicg.github.io/cookie-store/#cookie-maximum-name-value-pair-size
const maxNameValuePairSize = 4096

/**
 *
 *
 * @param {*} value
 * @return {*} 
 */
function isCTLExcludingHtab(value) {
  if (value.length === 0) {
    return false
  }

  for (const char of value) {
    const code = char.charCodeAt(0)

    if (
      (code >= 0x00 || code <= 0x08) ||
      (code >= 0x0A || code <= 0x1F) ||
      code === 0x7F
    ) {
      return false
    }
  }
}

/**
 CHAR           = <any US-ASCII character (octets 0 - 127)>
 token          = 1*<any CHAR except CTLs or separators>
 separators     = "(" | ")" | "<" | ">" | "@"
                | "," | ";" | ":" | "\" | <">
                | "/" | "[" | "]" | "?" | "="
                | "{" | "}" | SP | HT
 * @param {string} name
 */
function validateCookieName(name) {
  for (const char of name) {
    const code = char.charCodeAt(0)

    if (
      (code <= 0x20 || code > 0x7F) ||
      char === '(' ||
      char === ')' ||
      char === '>' ||
      char === '<' ||
      char === '@' ||
      char === ',' ||
      char === ';' ||
      char === ':' ||
      char === '\\' ||
      char === '"' ||
      char === '/' ||
      char === '[' ||
      char === ']' ||
      char === '?' ||
      char === '=' ||
      char === '{' ||
      char === '}'
    ) {
      throw new Error('Invalid cookie name')
    }
  }
}


/**
 cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
                       ; US-ASCII characters excluding CTLs,
                       ; whitespace DQUOTE, comma, semicolon,
                       ; and backslash
 * @param {string} value
 */
function validateCookieValue(value) {
  for (const char of value) {
    const code = char.charCodeAt(0)

    if (
      code < 0x21 || // exclude CTLs (0-31)
      code === 0x22 ||
      code === 0x2C ||
      code === 0x3B ||
      code === 0x5C ||
      code > 0x7E // non-ascii
    ) {
      throw new Error('Invalid header value')
    }
  }
}


/**
 * path-value        = <any CHAR except CTLs or ";">
 * @param {string} path
 */
function validateCookiePath(path) {
  for (const char of path) {
    const code = char.charCodeAt(0)

    if (code < 0x21 || char === ';') {
      throw new Error('Invalid cookie path')
    }
  }
}


/**
 * I have no idea why these values aren't allowed to be honest,
 * but Deno tests these. - Khafra
 * @param {string} domain
 */
function validateCookieDomain(domain) {
  if (
    domain.startsWith('-') ||
    domain.endsWith('.') ||
    domain.endsWith('-')
  ) {
    throw new Error('Invalid cookie domain')
  }
}


/**
 * @see https://www.rfc-editor.org/rfc/rfc7231#section-7.1.1.1
 * @param {number|Date} date
  IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT
  ; fixed length/zone/capitalization subset of the format
  ; see Section 3.3 of [RFC5322]

  day-name     = %x4D.6F.6E ; "Mon", case-sensitive
              / %x54.75.65 ; "Tue", case-sensitive
              / %x57.65.64 ; "Wed", case-sensitive
              / %x54.68.75 ; "Thu", case-sensitive
              / %x46.72.69 ; "Fri", case-sensitive
              / %x53.61.74 ; "Sat", case-sensitive
              / %x53.75.6E ; "Sun", case-sensitive
  date1        = day SP month SP year
                  ; e.g., 02 Jun 1982

  day          = 2DIGIT
  month        = %x4A.61.6E ; "Jan", case-sensitive
              / %x46.65.62 ; "Feb", case-sensitive
              / %x4D.61.72 ; "Mar", case-sensitive
              / %x41.70.72 ; "Apr", case-sensitive
              / %x4D.61.79 ; "May", case-sensitive
              / %x4A.75.6E ; "Jun", case-sensitive
              / %x4A.75.6C ; "Jul", case-sensitive
              / %x41.75.67 ; "Aug", case-sensitive
              / %x53.65.70 ; "Sep", case-sensitive
              / %x4F.63.74 ; "Oct", case-sensitive
              / %x4E.6F.76 ; "Nov", case-sensitive
              / %x44.65.63 ; "Dec", case-sensitive
  year         = 4DIGIT

  GMT          = %x47.4D.54 ; "GMT", case-sensitive

  time-of-day  = hour ":" minute ":" second
              ; 00:00:00 - 23:59:60 (leap second)

  hour         = 2DIGIT
  minute       = 2DIGIT
  second       = 2DIGIT
 */
function toIMFDate(date) {
  if (typeof date === 'number') {
    date = new Date(date)
  }

  const days = [
    'Sun', 'Mon', 'Tue', 'Wed',
    'Thu', 'Fri', 'Sat'
  ]

  const months = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
  ]

  const dayName = days[date.getUTCDay()]
  const day = date.getUTCDate().toString().padStart(2, '0')
  const month = months[date.getUTCMonth()]
  const year = date.getUTCFullYear()
  const hour = date.getUTCHours().toString().padStart(2, '0')
  const minute = date.getUTCMinutes().toString().padStart(2, '0')
  const second = date.getUTCSeconds().toString().padStart(2, '0')

  return `${dayName}, ${day} ${month} ${year} ${hour}:${minute}:${second} GMT`
}

/**
 max-age-av        = "Max-Age=" non-zero-digit *DIGIT
                       ; In practice, both expires-av and max-age-av
                       ; are limited to dates representable by the
                       ; user agent.
 * @param {number} maxAge
 */
function validateCookieMaxAge(maxAge) {
  if (maxAge < 0) {
    throw new Error('Invalid cookie max-age')
  }
}


/**
 * @see https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1
 * @param {import('./index').Cookie} cookie
 */
function stringify(cookie) {
  if (cookie.name.length === 0) {
    return null
  }

  validateCookieName(cookie.name)
  validateCookieValue(cookie.value)

  const out = [`${cookie.name}=${cookie.value}`]

  // https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-prefixes-00#section-3.1
  // https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-prefixes-00#section-3.2
  if (cookie.name.startsWith('__Secure-')) {
    cookie.secure = true
  }

  if (cookie.name.startsWith('__Host-')) {
    cookie.secure = true
    cookie.domain = null
    cookie.path = '/'
  }

  if (cookie.secure) {
    out.push('Secure')
  }

  if (cookie.httpOnly) {
    out.push('HttpOnly')
  }

  if (typeof cookie.maxAge === 'number') {
    validateCookieMaxAge(cookie.maxAge)
    out.push(`Max-Age=${cookie.maxAge}`)
  }

  if (cookie.domain) {
    validateCookieDomain(cookie.domain)
    out.push(`Domain=${cookie.domain}`)
  }

  if (cookie.path) {
    validateCookiePath(cookie.path)
    out.push(`Path=${cookie.path}`)
  }

  if (cookie.expires && cookie.expires.toString() !== 'Invalid Date') {
    out.push(`Expires=${toIMFDate(cookie.expires)}`)
  }

  if (cookie.sameSite) {
    out.push(`SameSite=${cookie.sameSite}`)
  }

  for (const part of cookie.unparsed) {
    if (!part.includes('=')) {
      throw new Error('Invalid unparsed')
    }

    const [key, ...value] = part.split('=')

    out.push(`${key.trim()}=${value.join('=')}`)
  }

  return out.join('; ')
}

/** https://github.com/nodejs/undici/blob/main/lib/cookies/util.js */

const ALGORITHM = {

  /**
   * GCM is an authenticated encryption mode that
   * not only provides confidentiality but also 
   * provides integrity in a secured way
   * */
  BLOCK_CIPHER: 'aes-256-gcm',

  /**
   * 128 bit auth tag is recommended for GCM
   */
  AUTH_TAG_BYTE_LEN: 16,

  /**
   * NIST recommends 96 bits or 12 bytes IV for GCM
   * to promote interoperability, efficiency, and
   * simplicity of design
   */
  IV_BYTE_LEN: 12,

  /**
   * Note: 256 (in algorithm name) is key size. 
   * Block size for AES is always 128
   */
  KEY_BYTE_LEN: 32,

  /**
   * To prevent rainbow table attacks
   * */
  SALT_BYTE_LEN: 16
};

/**
 *
 *
 * @param {*} message
 * @return {*} 
 */
function browserEncode(message) {
  // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
  let enc = new TextEncoder();
  return enc.encode(message);
}

/**
 *
 *
 * @param {*} encodedmessage
 * @return {*} 
 */
function browserDecode(encodedmessage) {
  // https://www.w3docs.com/learn-javascript/textdecoder-and-textencoder.html
  let enc = new TextDecoder();
  return enc.decode(encodedmessage);
}

/**
 * randomBytes
 * 
 * Browser implementation of crypto.randomBytes
 * 
 * Reference https://gist.github.com/alexdiliberto/39a4ad0453310d0a69ce
 *
 * @return {*} 
 */
function randomBytes() {
  var crypto = (self.crypto || self.msCrypto), QUOTA = 65536;
  return function (n) {
    var a = new Uint8Array(n);
    for (var i = 0; i < n; i += QUOTA) {
      crypto.getRandomValues(a.subarray(i, i + Math.min(n - i, QUOTA)));
    }
    return a;
  };
}

/**
 * getIV
 * 
 * Function to get a IV value using a standard IV byte length
 *
 */
function getIV() {
  if (typeof self !== 'undefined' && (self.crypto || self.msCrypto)) {
    return randomBytes(ALGORITHM.IV_BYTE_LEN)
  }
  return crypto.randomBytes(ALGORITHM.IV_BYTE_LEN);
};

/**
 * getRandomKey
 * 
 * Function to get a Key for a Crypto.CipherIV key
 *
 */
function getRandomKey() {
  if (typeof self !== 'undefined' && (self.crypto || self.msCrypto)) {
    return randomBytes(ALGORITHM.KEY_BYTE_LEN)
  }
  return crypto.randomBytes(ALGORITHM.KEY_BYTE_LEN)
};

/**
 * getSalt
 * 
 * Function to get a salt of specific byte length 
 * 
 * To prevent rainbow table attacks
 */
function getSalt() {
  if (typeof self !== 'undefined' && (self.crypto || self.msCrypto)) {
    return randomBytes(ALGORITHM.SALT_BYTE_LEN)
  }
  return crypto.randomBytes(ALGORITHM.SALT_BYTE_LEN)
};

/**
 * 
 * getKeyFromPassword
 * 
 * @param {Buffer} password - The password to be used for generating key
 * 
 * To be used when key needs to be generated based on password.
 * The caller of this function has the responsibility to clear 
 * the Buffer after the key generation to prevent the password 
 * from lingering in the memory
*/
function getKeyFromPassword(password, salt) {
  return crypto.scryptSync(password, salt, ALGORITHM.KEY_BYTE_LEN);
}

/**
* 
* cryptoencrypt
* 
* @param {Buffer} messagetext - The clear text message to be encrypted
* @param {Buffer} key - The key to be used for encryption
* 
* The caller of this function has the responsibility to clear 
* the Buffer after the encryption to prevent the message text 
* and the key from lingering in the memory
*/
function cryptoencrypt(messagetext, key) {
  const iv = getIV();
  const cipher = crypto.createCipheriv(
    ALGORITHM.BLOCK_CIPHER, key, iv,
    { 'authTagLength': ALGORITHM.AUTH_TAG_BYTE_LEN });
  let encryptedMessage = cipher.update(messagetext);
  encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);
  return Buffer.concat([iv, encryptedMessage, cipher.getAuthTag()]);
}

/**
* 
* cryptodecrypt
* 
* @param {Buffer} ciphertext - Cipher text
* @param {Buffer} key - The key to be used for decryption
* 
* The caller of this function has the responsibility to clear 
* the Buffer after the decryption to prevent the message text 
* and the key from lingering in the memory
*/
function cryptodecrypt(ciphertext, key) {
  const authTag = ciphertext.slice(-16);
  const iv = ciphertext.slice(0, 12);
  const encryptedMessage = ciphertext.slice(12, -16);
  const decipher = crypto.createDecipheriv(
    ALGORITHM.BLOCK_CIPHER, key, iv,
    { 'authTagLength': ALGORITHM.AUTH_TAG_BYTE_LEN });
  decipher.setAuthTag(authTag);
  let messagetext = decipher.update(encryptedMessage);
  messagetext = Buffer.concat([messagetext, decipher.final()]);
  return messagetext;
}

/**
 *
 * encrypt
 *
 * @param {*} actionFunction
 * @param {string} [salt=""]
 * @param {number} [index=1] Value is the messagetext to be encryptedand decrypted. Use the index of value as the index property's value
 * @param {*} [encrypter=cryptoencrypt]
 * @return {*} 
 */
function encrypt(actionFunction, salt = "", index = 1, encrypter = cryptoencrypt) {
  return function (...args) {
    let options = ["aes-256-ctr", "sha256", "base64", { logger: console.log }]
    args[index] = encrypter(args[index], salt, ...options);
    return actionFunction(...args);
  };
}

/**
 *
 * decrypt
 *
 * @param {*} actionFunction
 * @param {string} [salt=""]
 * @param {number} [index=1] Value is the messagetext to be encryptedand decrypted. Use the index of value as the index property's value
 * @param {*} [decrypter=cryptodecrypt]
 * @return {*} 
 */
function decrypt(actionFunction, salt = "", index = 1, decrypter = cryptodecrypt) {
  return function (...args) {
    let options = ["aes-256-ctr", "sha256", "base64", { logger: console.log }]
    let data = actionFunction(...args);
    args[index] = decrypter(data, salt, ...options);
    return args[index];
  };
}

/**
 *
 * encryptRecursive
 *
 * @param {*} actionFunction
 * @param {string} [salt=""]
 * @param {*} [encrypter=cryptoencrypt]
 * @return {*} 
 */
function encryptRecursive(actionFunction, salt = "", encrypter = cryptoencrypt) {
  return (...args) => actionFunction(...args).map(v => encrypter(v, salt));
}

/**
 *
 * decryptRecursive
 *
 * @param {*} actionFunction
 * @param {string} [salt=""]
 * @param {*} [decrypter=cryptodecrypt]
 * @return {*} 
 */
function decryptRecursive(actionFunction, salt = "", decrypter = cryptodecrypt) {
  return (...args) => actionFunction(...args).map(v => decrypter(v, salt));
}

/**
 *
 * getCookie
 * Basic set cookies function does not include the encryption decryption - please include
 * 
 * // returns the cookie with the given name,
 * // or undefined if not found
 * // Reference https://javascript.info/cookie
 *
 * @param {*} name
 * @return {*} 
 */
function getCookie(name) {
  let matches = document.cookie.match(new RegExp(
    "(?:^|; )" + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + "=([^;]*)"
  ));
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

/**
 * 
 * setCookie
 * Basic set cookies function does not include the encryption decryption - please include
 * 
 * // Reference https://javascript.info/cookie
 *
 * @param {*} name
 * @param {*} value
 * @param {*} [attributes={}]
 */
function setCookie(name, value, attributes = {}) {
  attributes = {
    path: '/',
    ...attributes
  };

  if (attributes.expires instanceof Date) {
    attributes.expires = attributes.expires.toUTCString();
  }
  let updatedCookie = encodeURIComponent(name) + "=" + encodeURIComponent(value);
  for (let attributeKey in attributes) {
    updatedCookie += "; " + attributeKey;
    let attributeValue = attributes[attributeKey];
    if (attributeValue !== true) {
      updatedCookie += "=" + attributeValue;
    }
  }
  document.cookie = updatedCookie;
}

/**
 * 
 * deleteCookie
 * Basic delete cookies function does not include the encryption decryption - please include
 * 
 * // Example of use:
 * // setCookie('user', 'John', {secure: true, 'max-age': 3600});
 * // Reference https://javascript.info/cookie
 *
 * @param {*} name
 */
function deleteCookie(name) {
  setCookie(name, "", {
    'max-age': -1
  })
}

// const defaults = {
//   encrypt,
//   decrypt,
//   cryptoencrypt,
//   cryptodecrypt,
//   encryptRecursive,
//   decryptRecursive,
//   getRandomKey,
//   getSalt,
//   getIV,
//   getKeyFromPassword
// }

// module.exports.default = defaults;

if (!isBrowser()) {

  module.exports.maxAttributeValueSize = maxAttributeValueSize;
  module.exports.maxNameValuePairSize = maxNameValuePairSize;
  module.exports.isCTLExcludingHtab = isCTLExcludingHtab;
  module.exports.validateCookieName = validateCookieName;
  module.exports.validateCookieValue = validateCookieValue;
  module.exports.validateCookiePath = validateCookiePath;
  module.exports.validateCookieDomain = validateCookieDomain;
  module.exports.toIMFDate = toIMFDate;
  module.exports.validateCookieMaxAge = validateCookieMaxAge;
  module.exports.stringify = stringify;

  /** @type { BLOCK_CIPHER, AUTH_TAG_BYTE_LEN, IV_BYTE_LEN, KEY_BYTE_LEN, SALT_BYTE_LEN } */
  module.exports.ALGORITHM = ALGORITHM;

  module.exports.getIV = getIV;
  module.exports.getRandomKey = getRandomKey;
  module.exports.getSalt = getSalt;
  module.exports.getKeyFromPassword = getKeyFromPassword;
  module.exports.cryptoencrypt = cryptoencrypt;
  module.exports.cryptodecrypt = cryptodecrypt;
  module.exports.encrypt = encrypt;
  module.exports.decrypt = decrypt;
  module.exports.encryptRecursive = encryptRecursive;
  module.exports.decryptRecursive = decryptRecursive;

  module.exports.getCookie = getCookie;
  module.exports.setCookie = setCookie;
  module.exports.deleteCookie = deleteCookie;

  // module.exports.generateJwtSecret = generateJwtSecret;
  // module.exports.nonce = nonce;
  // module.exports.randomString = randomString;
  module.exports.randomBytes = randomBytes;
  module.exports.browserEncode = browserEncode;
  module.exports.browserDecode = browserDecode;

}
