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
