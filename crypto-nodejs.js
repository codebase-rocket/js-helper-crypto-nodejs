// Info: Boilerplate library. Contains Functions related to Crypto and Encryptions (For NodeJS only and not browsers)
'use strict';

// Shared Dependencies (Managed by Loader)
var Lib = {};

// Node JS inbuilt module for Crypto Functions (Private scope)
const NodeCrypto = require('crypto');

// UUIDv4 Generator Library (Private scope)
const { v4: Uuid } = require('uuid');

// Base Convertor Library (Private scope)
const BaseConvertor = require('any-base');

// Exclusive Dependencies
var CONFIG = require('./config'); // Loader can override it with Custom-Config


/////////////////////////// Module-Loader START ////////////////////////////////

  /********************************************************************
  Load dependencies and configurations

  @param {Set} shared_libs - Reference to libraries already loaded in memory by other modules
  @param {Set} config - Custom configuration in key-value pairs

  @return nothing
  *********************************************************************/
  const loader = function(shared_libs, config){

    // Shared Dependencies (Must be loaded in memory already)
    Lib.Utils = shared_libs.Utils;
    Lib.Debug = shared_libs.Debug;

    // Override default configuration
    if( !Lib.Utils.isNullOrUndefined(config) ){
      Object.assign(CONFIG, config); // Merge custom configuration with defaults
    }

  };

//////////////////////////// Module-Loader END /////////////////////////////////



///////////////////////////// Module Exports START /////////////////////////////
module.exports = function(shared_libs, config){

  // Run Loader
  loader(shared_libs, config);

  // Return Public Funtions of this module
  return Crypto;

};//////////////////////////// Module Exports END //////////////////////////////



///////////////////////////Public Functions START//////////////////////////////
const Crypto = { // Public functions accessible by other modules

  /********************************************************************
  Generate random string of valid characters only
  Note: This function has dependency on NodeJS Crypto Library. Cannot be used in Browser.

  @param {String} charset - The string of character for superset
  @param {Integer} length - The length of random string to be generated

  @return {String} - Newly generated string of random characters
  *********************************************************************/
  generateRandomString: function(charset, length){

    // Ref: https://stackoverflow.com/a/25690754/1449954 (Method 2)

    var charset_length = charset.length;
    var random_buffer = NodeCrypto.randomBytes(length); // Create a Buffer of 'n' random bytes. 1 byte for each character of 8bit.
    var output = new Array(length); // Initialize empty array of defined length

    var cursor = 0;
    for(var i = 0; i < length; i++){
      cursor += random_buffer[i];
      output[i] = charset[cursor % charset_length];
    }

    return output.join(''); // Create string out of result array

  },


  /********************************************************************
  Generate random string with base36-time as prefix, and random base36-string as padding
  Note: This function has dependency on NodeJS Crypto Library. Cannot be used in Browser.

  @param {String} time - Current Unix-Time in seconds
  @param {Integer} [min_length] - (Optional) Minimum length of random string to be generated. Adds random string as padding
  @param {Integer} [epoch_offset] - (Optional) Set a new Epoch starting date

  @return {String} - Newly generated string of time + random characters (in base36)
  *********************************************************************/
  generateTimeRandomString: function(time, min_length, epoch_offset){

    // Calculate time with epoch offset (only if sent in params)
    if( !Lib.Utils.isNullOrUndefined(epoch_offset) ){
      time = time - epoch_offset;
    }

    // Convert time into base36 string
    var result = Crypto.intToBase36(time);

    // Add padding with random strings if min_length is specified
    if(
      !Lib.Utils.isNullOrUndefined(min_length) && // Specified in param
      result.length < min_length // Current length is less then min-length
    ){
      result += Crypto.generateRandomString(
        CONFIG.BASE36_CHARSET,
        min_length - result.length // Length of padding
      )
    }

    // Return
    return result;

  },


  /********************************************************************
  Give random UUIDv4 string. 36 Char HexaDecimal/Base16

  // No Params

  @return {String} - Random UUIDv4
  *********************************************************************/
  generateUUID: function(){

    return Uuid();

  },


  /********************************************************************
  Give Short random UUIDv4 string. 25 Char long - Base36

  // No Params

  @return {String} - Random Short UUIDv4
  *********************************************************************/
  generateShortUUID: function(){

    // Generate a UUID
    var uuid_buffer = Buffer.alloc(16);
    Uuid(null, uuid_buffer, 0); // Generate UUID in Buffer as Array of Bytes

    // Convert uuid in hex to base36
    return _Crypto.hexToBase36( uuid_buffer.toString('hex') ).padEnd(25, '0');

  },


  /********************************************************************
  Give MD5 hash of a string. 32 Char HexaDecimal/Base16

  @param {String} str - String to be hashed

  @return {String} - MD5 hash of String
  *********************************************************************/
  md5String: function(str){

    return NodeCrypto.createHash('md5').update(str).digest('hex');

  },


  /********************************************************************
  Give SHA256 hash of a string. Output: 64 Char HexaDecimal/Base16

  @param {String} str - String to be hashed
  @param {String} [secret] - (Optional) Secret used for hashing

  @return {String} - SHA256 hash of String
  *********************************************************************/
  sha256String: function(str, secret){

    // Set secret as '' if null or undefined
    if( Lib.Utils.isNullOrUndefined(secret) ){
      secret = '';
    }

    return NodeCrypto.createHmac('sha256', secret).update(str).digest('hex');

  },


  /********************************************************************
  Encrypt a String using AES-CBC. Output: Encrypted HexaDecimal/Base16

  @param {String} str - String to be Encrypted
  @param {String} secret - Secret-Key for encryption

  @return {String} - Encrypted String
  *********************************************************************/
  aesEncryption: function(str, secret){

    // Create MD5-Hash of Secret
    var secret_hash_buffer = NodeCrypto.createHash('md5').update(secret).digest();

    // Extract 16 Byte from MD5-Hash
    var secret_hash_buffer_16bytes = secret_hash_buffer.slice(0, 16);

    // Create initialization vector
    var initialization_vector = NodeCrypto.createHash('md5').update(secret_hash_buffer_16bytes).update(secret).digest();

    // Create Cipher
    var cipher = NodeCrypto.createCipheriv('aes-128-cbc', secret_hash_buffer_16bytes, initialization_vector);

    // Return Encrypted String
    return cipher.update(str, 'utf8', 'hex') + cipher.final('hex');

  },


  /********************************************************************
  Decrypt a String encrypted using AES-CBC. Output: Decrypted String

  @param {String} str - String to be Decrypted
  @param {String} secret - Secret-Key used for encryption

  @return {String} - Decrypted String
  *********************************************************************/
  aesDecryption: function(str, secret){

    // Create MD5-Hash of Secret
    var secret_hash_buffer = NodeCrypto.createHash('md5').update(secret).digest();

    // Extract 16 Byte from MD5-Hash
    var secret_hash_buffer_16bytes = secret_hash_buffer.slice(0, 16);

    // Create initialization vector
    var initialization_vector = NodeCrypto.createHash('md5').update(secret_hash_buffer_16bytes).update(secret).digest();

    // Create Decipher
    var cipher = NodeCrypto.createDecipheriv('aes-128-cbc', secret_hash_buffer_16bytes, initialization_vector);

    // Return Encrypted String
    return cipher.update(str, 'hex', 'utf8') + cipher.final('utf8');

  },


  /********************************************************************
  Encrypt a String using AES-CBC. Output: Encrypted HexaDecimal/Base16

  @param {String} str - String to be Encrypted
  @param {String} secret - Secret-Key for encryption

  @return {String} - Encrypted String
  *********************************************************************/
  aesEncryptionLegacy: function(str, secret){

    // Create Cipher
    var cipher = NodeCrypto.createCipher('aes-128-cbc', secret);

    // Return Encrypted String
    return cipher.update(str, 'utf8', 'hex') + cipher.final('hex');

  },


  /********************************************************************
  Decrypt a String encrypted using AES-CBC. Output: Decrypted String

  @param {String} str - String to be Decrypted
  @param {String} secret - Secret-Key used for encryption

  @return {String} - Decrypted String
  *********************************************************************/
  aesDecryptionLegacy: function(str, secret){

    // Create Cipher
    var cipher = NodeCrypto.createDecipher('aes-128-cbc', secret);

    // Return Encrypted String
    return cipher.update(str, 'hex', 'utf8') + cipher.final('utf8');

  },


  /********************************************************************
  Give Base36 equivalent of a number

  @param {Integer} num - Number to be converted

  @return {String} - Base36 of String
  *********************************************************************/
  intToBase36: function(num){

    // Return
    return BaseConvertor(CONFIG.INT_CHARSET, CONFIG.BASE36_CHARSET)(num + '');

  },


  /********************************************************************
  Give number equivalent of Base36 string

  @param {String} str - Base36 String to be converted

  @return {Integer} - Number
  *********************************************************************/
  base36ToInt: function(str){

    // Return
    return parseInt( BaseConvertor(CONFIG.BASE36_CHARSET, CONFIG.INT_CHARSET)(str) );

  },


  /********************************************************************
  Give Base64 equivalent of a string

  @param {Object} obj - Buffer Object

  @return {String} - Base64 of Buffer-Object
  *********************************************************************/
  bufferToBase64: function(obj){

    // Return
    return obj.toString('base64');

  },


  /********************************************************************
  Give Base64 equivalent of a string

  @param {String} str - String to be converted

  @return {String} - Base64 of String
  *********************************************************************/
  stringToBase64: function(str){

    // Return
    return Buffer.from(str).toString('base64');

  },


  /********************************************************************
  Give ascii string equivalent of Base64

  @param {String} str - String to be converted

  @return {String} - Ascii of Base64
  *********************************************************************/
  base64ToString: function(str){

    return Buffer.from(str, 'base64').toString();

  },


  /********************************************************************
  Convert original Base64 string to URL-Safe Base64 by changing '+' to '-', '/' to '_'. Also removes trailling padding chars '='

  @param {String} str - String to be converted

  @return {String} - URL Encoded Base64 of String
  *********************************************************************/
  urlEncodeBase64: function(str){

    // Return
    return str
          .replace(/=/g, '') // Removes extra padding from base64. The length of base64 String is in multiple of 3. If not, the output is padded with '='
          .replace(/\//g, '_') // Replace '/' with '_'
          .replace(/\+/g, '-'); // Replace '+' with '-'

  },


  /********************************************************************
  Convert URL-Safe Base64 string to original Base64 by changing '-' to '+', '_' to '/'. Also add trailling padding chars '='

  @param {String} str - String to be converted

  @return {String} - Orignal Base64 of String
  *********************************************************************/
  urlDecodeBase64: function(str){

    // Return empty/null/undefined string as it is
    if(!str){
      return str;
    }

    // Calculate length with padding required to make string length multiple of 3
    var pad_count = (str.length % 3);

    // Add padding char to string
    if(pad_count>0) str += '=';
    if(pad_count>1) str += '=';

    // Return
    return str
          .replace(/_/g, '/') // Replace '_' with '/'
          .replace(/-/g, '+'); // Replace '-' with '+'

  },

};///////////////////////////Public Functions END//////////////////////////////



//////////////////////////Private Functions START//////////////////////////////
const _Crypto = { // Private functions accessible within this modules only

  /********************************************************************
  Give Base62 string equivalent of Hex

  @param {String} str - String to be converted

  @return {String} - Base36 of Hex (25 Chars)
  *********************************************************************/
  hexToBase36: function(str){

    return BaseConvertor(CONFIG.HEX_CHARSET, CONFIG.BASE36_CHARSET)(str);

  },

};//////////////////////////Private Functions END//////////////////////////////
