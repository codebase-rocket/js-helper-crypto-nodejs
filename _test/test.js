// Info: Test Cases
'use strict';

// Shared Dependencies
var Lib = {};

// Dependencies
Lib.Utils = require('js-helper-utils');
Lib.Debug = require('js-helper-debug')(Lib);
const Crypto = require('js-helper-crypto-nodejs')(Lib);


/////////////////////////////STAGE SETUP///////////////////////////////////////

// Load dummy event data
const random_charset = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`;

///////////////////////////////////////////////////////////////////////////////


/////////////////////////////////TESTS/////////////////////////////////////////

// Test .generateRandomString() function
console.log(
  `generateRandomString(${random_charset}, 10):`,
  Crypto.generateRandomString(random_charset, 10)
)


// Test .generateUUID() function
console.log(
  `generateUUID():`,
  Crypto.generateUUID()
)


// Test .generateShortUUID() function
console.log(
  `generateShortUUID():`,
  Crypto.generateShortUUID()
)


// Test .intToBase36() function
console.log( // Output: 7clzi
  `intToBase36(12345678):`,
  Crypto.intToBase36(12345678)
)


// Test .base36ToInt() function
console.log( // Output: 12345678
  `base36ToInt('7clzi'):`,
  Crypto.base36ToInt('7clzi')
)


// Test .bufferToBase64() function
var buff_obj = require('fs').readFileSync('1x1_pixel.png');
console.log( // Output: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=
  `bufferToBase64(buff_obj):`,
  Crypto.bufferToBase64(buff_obj)
)


// Test .generateTimeRandomString() function
console.log( // Output: 12345678
  `generateTimeRandomString('1593878946'):`,
  Crypto.generateTimeRandomString('1593878946')
)

console.log( // Output: 12345678
  `generateTimeRandomString('1593878946', 16):`, // With Padding
  Crypto.generateTimeRandomString('1593878946',16)
)

console.log( // Output: 12345678
  `generateTimeRandomString('1593878946', null, 1577836800):`, // With Epoch offset (1/jan/2020 = 1577836800)
  Crypto.generateTimeRandomString('1593878946', null, 1577836800)
)


// Test .aesEncryption() function
var test_string = 'Hello-World 123';
var test_key = 'My-Key 123';
var encrypted_text = Crypto.aesEncryption(test_string, test_key)
console.log(
  `aesEncryption(${test_string}, ${test_key}):`,
  encrypted_text
)

// Test .aesDecryption() function
console.log(
  `aesDecryption(${encrypted_text}, ${test_key}):`,
  Crypto.aesDecryption(encrypted_text, test_key)
)


// Test .aesEncryptionLegacy() function
var test_string = 'Hello-World 123';
var test_key = 'My-Key 123';
var encrypted_text = Crypto.aesEncryptionLegacy(test_string, test_key)
console.log(
  `aesEncryptionLegacy(${test_string}, ${test_key}):`,
  encrypted_text
)

// Test .aesDecryptionLegacy() function
console.log(
  `aesDecryptionLegacy(${encrypted_text}, ${test_key}):`,
  Crypto.aesDecryptionLegacy(encrypted_text, test_key)
)

///////////////////////////////////////////////////////////////////////////////
