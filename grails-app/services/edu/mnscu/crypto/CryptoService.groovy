package edu.mnscu.crypto

import grails.transaction.Transactional

import javax.crypto.Cipher
import javax.crypto.Mac
import java.security.Key

@Transactional
class CryptoService {

    /**
     *
     * @param plainText - plain text string in which to encrypt
     * @param key - AES key
     * @param algo - Algorithm (tested with AES and RSA)
     * @return - returns encrypted string in base64
     */
    public static String encrypt(String plainText, Key key, String algo) {
        def encryptedBase64 = null
        try {
            Cipher cipher = Cipher.getInstance(algo)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            byte[] encryptedBytes = cipher.doFinal(plainText.bytes)
            encryptedBase64 = encryptedBytes.encodeBase64()
        } catch (Exception e) {
            // Handle exceptions
            e.printStackTrace()
        }
        return encryptedBase64
    }

    /**
     *
     * @param encryptedBase64 - encrypted string in base 64
     * @param key - AES key
     * @param algo - Algorithm (tested with AES and RSA)
     * @return - returns decrypted string in plain text
     */
    public static String decrypt(String encryptedBase64, Key key, String algo) {
        def decryptedText = null
        try {
            Cipher cipher = Cipher.getInstance(algo)
            cipher.init(Cipher.DECRYPT_MODE, key)
            byte[] decryptedBytes = cipher.doFinal(encryptedBase64.decodeBase64())
            decryptedText = new String(decryptedBytes)
        } catch (Exception e) {
            // Handle exceptions
            e.printStackTrace()
        }
        return decryptedText
    }

    /**
     *
     * @param plainText - plain text string that we want to hash
     * @param secretKey - HmacSha256 key
     * @return - returns hash as base64 string
     */
    public static String hmacSha256(String plainText, Key secretKey) {
        String result
        try {
            // get an hmac_sha1 Mac instance and initialize with the signing key
            Mac mac = Mac.getInstance("HmacSha256")
            mac.init(secretKey)
            // compute the hmac on input plainText bytes
            byte[] rawHmac = mac.doFinal(plainText.getBytes())
            result = rawHmac.encodeBase64()
        }
        catch (Exception e) {
            // Handle exceptions
            e.printStackTrace()
        }
        return result
    }


}
