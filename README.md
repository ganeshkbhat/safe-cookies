# safecookie
Wrap the `cookie libraries` functions like `somecookie.get, somecookie.set, or other setters and getters` with a `safer` `encrypt` - `decrypt` function :: should work with most libraries. 

The `encrypt`, `decrypt` function wraps a normal `setter (encrypt)` and `getter (decrypt)` functions with crypto functions that help `create safer value storage options for procedures` like `localStorage`, `cookies`, `password storage in database` etc. 

Do take a look at the [architectural concept here](https://medium.com/@ganeshsurfs/toying-with-the-idea-of-storage-security-9fdd65707d6e)

You can find the [demos here](https://github.com/ganeshkbhat/safe-cookies/tree/main/demos)

#### INSTALLATION

`npm install safecookie`

`npm install safecookies`


#### USAGE ONE:

```

import pkg from "safecookie";
const { encrypt, decrypt, encryptRecursive, decryptRecursive, cryptoencrypt, cryptodecrypt, getKeyFromPassword } = pkg;

let key = getKeyFromPassword("password", "testsalt");
let yourFnThatReturnsValue = (v) => { console.log(v.toString("base64")); return v; }

// 
// USAGE:
//  
//    encrypt(yourfunc, key_generated, value_arg_index, cryptoencrypt) 
//
//    encrypt(yourFnThatReturnsValue, key, 0, cryptoencrypt) 
// 
// if the value to be encrypted is argument index 0 then use 0 
//      else use the index of the value argument
// 
// if the value to be encrypted is argument index 1 then use 1 
//      else use the index of the value argument
// 
//      yourfunc(value) =======> index is 0
//      yourfunc(something, value) ========> index is 1
// 

let cryptedfn = encrypt(yourFnThatReturnsValue, key, 0, cryptoencrypt) 
let cryptedtext = cryptedfn("Testing new crypter"); 
console.log(cryptedtext.toString("base64"));

let decryptedfn = decrypt(yourFnThatReturnsValue, key, 0, cryptodecrypt)
let decryptedtext = decryptedfn(cryptedtext);
console.log(decryptedtext.toString());

```

#### USAGE TWO:

```

import pkg from "safecookie";
const { encrypt, decrypt, encryptRecursive, decryptRecursive, cryptoencrypt, cryptodecrypt, getKeyFromPassword } = pkg;

let key = getKeyFromPassword("password", "testsalt");
let yourFnThatReturnsValue = (v) => { console.log(v.toString("base64")); return v; }

// 
// USAGE:
//  
//    encrypt(yourfunc, key_generated, value_arg_index, cryptoencrypt) 
//
//    encrypt(yourFnThatReturnsValue, key, 0, cryptoencrypt) 
// 
// if the value to be encrypted is argument index 0 then use 0 
//      else use the index of the value argument
// 
// if the value to be encrypted is argument index 1 then use 1 
//      else use the index of the value argument
// 
//      yourfunc(value) =======> index is 0
//      yourfunc(something, value) ========> index is 1
// 

let cryptedfn = encrypt(yourFnThatReturnsValue, key, 0, cryptoencrypt) 
let cryptedtext = cryptedfn("Testing new crypter"); 
console.log(cryptedtext.toString("base64"));

let decryptedfn = decrypt(yourFnThatReturnsValue, key, 0, cryptodecrypt)
let decryptedtext = decryptedfn(cryptedtext);
console.log(decryptedtext.toString());

```


#### NOTE:

###### Errors:

`TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object` occurs because of the crypto `cryptoencrypt` and `cryptodecrypt` function. 

- It basically means the encrypted data passed in not of the right format sent.
- It expects that what was send back from the set function of encrypt data function 
        is passed back to it in the same format
- The format of the encrypted data looks like this:
        `{ iv: 'uIF9gjowtvLDtUYMU0hQjg==', content: 'K129hrHxeBkg' }`
- You can also remove the implementation used and pass your own encrypting function you wish


#### TODO:

- Create a `browser` implementation
- Test with `React useState` functions
- Test with `tough cookies` package, `jsdom` in nodejs, etc
