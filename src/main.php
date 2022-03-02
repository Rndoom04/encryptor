<?php
    /*
     * Encryptor and decryptor library for PHP by Kollert Slavomí­r
     * version: 1.0
     * release date: 2.3.2022
     */

    namespace Rndoom04\encryptor;

    class encryptor {
        /* Encryption and decryption key - change to your secret password */
        private $encryption_key = "07ace6cf924872ec6e97975afef239a2";
        
        /* Encryption and decryption method - do not change! */
        private $encryption_method = "AES-128-CBC";
            
        /* Allowed algorithms */
        private $allowed_algorithms = [
            "AES-128-CBC",
            "AES-128-CBC-HMAC-SHA1",
            "AES-128-CFB",
            "AES-128-CFB1",
            "AES-128-CFB8",
            "AES-128-CTR",
            "AES-128-OFB",
            "AES-192-CBC",
            "AES-192-CFB",
            "AES-192-CFB1",
            "AES-192-CFB8",
            "AES-192-CTR",
            "AES-192-OFB",
            "AES-256-CBC",
            "AES-256-CBC-HMAC-SHA1",
            "AES-256-CFB",
            "AES-256-CFB1",
            "AES-256-CFB8",
            "AES-256-CTR",
            "AES-256-OFB",
            "BF-CBC",
            "BF-CFB",
            "BF-OFB",
            "CAMELLIA-128-CBC",
            "CAMELLIA-128-CFB",
            "CAMELLIA-128-CFB1",
            "CAMELLIA-128-CFB8",
            "CAMELLIA-128-OFB",
            "CAMELLIA-192-CBC",
            "CAMELLIA-192-CFB",
            "CAMELLIA-192-CFB1",
            "CAMELLIA-192-CFB8",
            "CAMELLIA-192-OFB",
            "CAMELLIA-256-CBC",
            "CAMELLIA-256-CFB",
            "CAMELLIA-256-CFB1",
            "CAMELLIA-256-CFB8",
            "CAMELLIA-256-OFB",
            "CAST5-CBC",
            "CAST5-CFB",
            "CAST5-OFB",
            "DES-CBC",
            "DES-CFB",
            "DES-CFB1",
            "DES-CFB8",
            "DES-EDE-CBC",
            "DES-EDE-CFB",
            "DES-EDE-OFB",
            "DES-EDE3-CBC",
            "DES-EDE3-CFB",
            "DES-EDE3-CFB1",
            "DES-EDE3-CFB8",
            "DES-EDE3-OFB",
            "DES-OFB",
            "DESX-CBC",
            "RC2-40-CBC",
            "RC2-64-CBC",
            "RC2-CBC",
            "RC2-CFB",
            "RC2-OFB"
        ];
        
        
        /**
         * Construct method
         * @param string $data
         * @param string $key | temporarily key, normal using global $encryption_key
         * @return string
        */
        public function __construct($key = null) {
            if (!empty($key)) {
                $this->encryption_key = $key;
            }
        }
        
        /**
         * Set global encryption key to encrypt and decrypt
         * @param string $key
         * @return bool
        */
        public function setKey($key) {
            if (!empty($key)) {
                $this->encryption_key = $key;
                return true;
            }
            
            return false;
        }
        
        /**
         * Set global algorithm method to encrypt and decrypt
         * @param string $method
         * @return bool
        */
        public function setAlgorithm($method) {
            if (!empty($method)) {
                // Is in allowed methods?
                if (in_array($method, $this->encryption_method)) {
                    $this->encryption_method = $method;
                    return true;
                } else {
                    return false;
                }
            }
            
            return false;
        }
        
        /**
         * Get allowed supported algorithms methods
         * @return array
        */
        public function getAlgorithms() {
            return $this->encryption_method;
        }

        /**
         * Encryption method - encrypt string to encrypted string
         * @param string $data
         * @param string $_key | temporarily key, normal using global $encryption_key
         * @return string
        */
        public function encrypt($data, $_key = null) {
            // Choose key to encrypt by
            if (!empty($_key)) {
                $key = $_key;
            } else {
                $key = $this->encryption_key;
            }
            
            // Encrypt method
            $plaintext = $data;
            $ivlen = openssl_cipher_iv_length($cipher = $this->encryption_method);
            $iv = openssl_random_pseudo_bytes($ivlen);
            $ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, $options = OPENSSL_RAW_DATA, $iv);
            $hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary = true);
            $ciphertext = base64_encode($iv . $hmac . $ciphertext_raw);
            
            // Return
            return $ciphertext;
        }
        
        /**
         * Decryption method - decrypt encrypted string to plain string
         * @param string $data
         * @param string $_key | temporarily key, normal using global $encryption_key
         * @return string
        */
        public function decrypt($data, $_key = null) {
            // Choose key to decrypt by
            if (!empty($_key)) {
                $key = $_key;
            } else {
                $key = $this->encryption_key;
            }
            
            // Decrypt method
            $c = base64_decode($data);
            $ivlen = openssl_cipher_iv_length($cipher = $this->encryption_method);
            $iv = substr($c, 0, $ivlen);
            $hmac = substr($c, $ivlen, $sha2len = 32);
            $ciphertext_raw = substr($c, $ivlen + $sha2len);
            $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options = OPENSSL_RAW_DATA, $iv);
            $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary = true);
            
            // Return
            if (hash_equals($hmac, $calcmac))
            {
                // Return original plaintext
                return $original_plaintext;
            }
            
            // Something went wrong
            return null;
        }
    }
?>
