ENCRYPTION AND DECRYPTION
=============

Compatible with PHP >= 7.0.

This is a library-template for writing custom PHP library functions

## Install

For PHP version **`>= 7.0`**:

```
composer require Rndoom04/encryptor
```

## How to use it

Firstly init the library by simply "use".

```
use Rndoom04\encryptor;
```

Load the library and let's encrypt.
```
$string_to_test = "Hello this is a text to encrypt.";
$encryptor = new \Rndoom04\encryptor\encryptor();
$encryptor->setKey("my-secret-key"); // Set key

$encrypted_string = $encryptor->encrypt($string_to_test); // Return encrypted string
$decrypted_string = $encryptor->decrypt($encrypted_string); // Encrypted string you can decrypt back to plain string
```
