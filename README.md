# safe-cookies
Wrap most of the cookie libraries with a safer encrypt - decrypt function - should work with most libraries



NOTE:

Errors:

`TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object` occurs becuase of the crypto function. 

- It basically means the encrypted data passed in not of the right format sent.
- It expects that what was send back from the set function of encrypt data function 
        is passed back to it in the same format
- The format of the encrypted data looks like this:
        `{ iv: 'uIF9gjowtvLDtUYMU0hQjg==', content: 'K129hrHxeBkg' }`
- You can also remove the implementation used and pass your own encrypting function you wish
- 
