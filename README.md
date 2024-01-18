# safe-cookies
Wrap most of the cookie libraries with a safer encrypt - decrypt function - should work with most libraries


USAGE ONE:

```

import pkg from "safecookie";
const { encrypt, decrypt, encryptRecursive, decryptRecursive, cryptoencrypt, cryptodecrypt, getKeyFromPassword } = pkg;

console.log("Testing new crypter");

let cryptedtext = encrypt((v) => { console.log(v.toString("base64")); return v; }, getKeyFromPassword("password", "testsalt"), 0, cryptoencrypt)("Testing new crypter");
console.log(cryptedtext.toString("base64"));

let decryptedtext = decrypt((v) => { console.log(v.toString("base64")); return v; }, getKeyFromPassword("password", "testsalt"), 0, cryptodecrypt)(cryptedtext);
console.log(decryptedtext.toString());

```

USAGE TWO:

```

import pkg from "safecookie";
const { encrypt, decrypt, encryptRecursive, decryptRecursive, cryptoencrypt, cryptodecrypt, getKeyFromPassword } = pkg;

console.log("Testing new crypter");

let cryptedtext = encrypt((v) => { console.log(v.toString("base64")); return v; }, getKeyFromPassword("password", "testsalt"), 0, cryptoencrypt)("Testing new crypter");
console.log(cryptedtext.toString("base64"));

let decryptedtext = decrypt((v) => { console.log(v.toString("base64")); return v; }, getKeyFromPassword("password", "testsalt"), 0, cryptodecrypt)(cryptedtext);
console.log(decryptedtext.toString());

```

NOTE:

Errors:

`TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object` occurs because of the crypto function. 

- It basically means the encrypted data passed in not of the right format sent.
- It expects that what was send back from the set function of encrypt data function 
        is passed back to it in the same format
- The format of the encrypted data looks like this:
        `{ iv: 'uIF9gjowtvLDtUYMU0hQjg==', content: 'K129hrHxeBkg' }`
- You can also remove the implementation used and pass your own encrypting function you wish
- 
