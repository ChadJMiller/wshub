package edu.mnscu.crypto

import grails.test.mixin.TestFor
import spock.lang.Specification

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

@TestFor(CryptoService)
class CryptoServiceSpec extends Specification {
    static String aes128Key
    static String hmacSha256Key
    static String publicRsaKey
    static String privateRsaKey

    def setupSpec() {

        //Generate keys for use during this test run
        aes128Key = getNewAES128Key()
        hmacSha256Key = getNewHmacSha256Key()
        def publicPrivateKey = getNewPublicPrivateRsaKey()
        publicRsaKey = publicPrivateKey.publicKey
        privateRsaKey = publicPrivateKey.privateKey

        //Display the generated keys
        println "AES128Key:\n${aes128Key}"
        println "hmacSha256Key:\n${hmacSha256Key}"
        println "publicRsaKey:\n${publicRsaKey}"
        println "privateRsaKey:\n${privateRsaKey}"
    }

    def cleanup() {
    }

    def getNewAES128Key() {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(128, new SecureRandom("wild oat seed".bytes))
        SecretKey sk = keyGenerator.generateKey()
        return sk.encoded.encodeBase64().toString()
    }

    def getNewHmacSha256Key() {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256")
        keyGenerator.init(256, new SecureRandom("wild oat seed".bytes))
        SecretKey sk = keyGenerator.generateKey()
        return sk.encoded.encodeBase64().toString()
    }

    def getNewPublicPrivateRsaKey() {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom("wild oat seed".bytes));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        return [publicKey: publicKey.encoded.encodeBase64(), privateKey: privateKey.encoded.encodeBase64()]
    }

    void "test encrypt/decrypt AES"() {
      given: "Given a key"
        Key key = new SecretKeySpec(aes128Key.decodeBase64(), 'AES')
      and:
        def str = "abc123"
      when: "When"
        def encryptedResult = service.encrypt(str, key, "AES")
        def decryptedResult = service.decrypt(encryptedResult, key, "AES")
        println "[original: ${str}, encrypted: ${encryptedResult}, decryptedResult: ${decryptedResult}]"
      then: "Then"
        str == decryptedResult

    }

    void "test hmacsha256"() {
      given: "Given a key"
        Key key = new SecretKeySpec(hmacSha256Key.decodeBase64(), 'HmacSHA256')
      when: "When"
        def hashedResult1 = service.hmacSha256('abc123', key)
        def hashedResult2 = service.hmacSha256('abc123', key)
        def hashedResult3 = service.hmacSha256('different', key)
      then: "Then"
        //hashing the same string yields the same results
        hashedResult1 == hashedResult2
        //hashing different things yields different results
        hashedResult3 != hashedResult2
        hashedResult3 != hashedResult1
    }

    void "test encrypt/decrypt RSA"() {
      given: "Given a key"
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateRsaKey.decodeBase64())
        KeySpec publicKeySpec = new X509EncodedKeySpec(publicRsaKey.decodeBase64())

        println privateKeySpec 
        println publicKeySpec
        KeyFactory keyFactory = KeyFactory.getInstance("RSA")
        Key privateKey = keyFactory.generatePrivate(privateKeySpec)
        Key publicKey = keyFactory.generatePublic(publicKeySpec)
      and:
        def str = "abc123"
      when: "When"
        def encryptedResult = service.encrypt(str, publicKey, "RSA")
        def decryptedResult = service.decrypt(encryptedResult, privateKey, "RSA")
        println "[original: ${str}, encrypted: ${encryptedResult}, decryptedResult: ${decryptedResult}]"

      then: "Then"
        str == decryptedResult
    }

    void "test encrypt/decrypt RSA - with public/private key usage reversed"() {
        println "dave is here"
      given: "Given a key"
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateRsaKey.decodeBase64())
        KeySpec publicKeySpec = new X509EncodedKeySpec(publicRsaKey.decodeBase64())

        println privateKeySpec 
        println publicKeySpec
        KeyFactory keyFactory = KeyFactory.getInstance("RSA")
        Key privateKey = keyFactory.generatePrivate(privateKeySpec)
        Key publicKey = keyFactory.generatePublic(publicKeySpec)
      and:
        def str = "abc123"
      when: "When"
        def encryptedResult = service.encrypt(str, privateKey, "RSA")
        def decryptedResult = service.decrypt(encryptedResult, publicKey, "RSA")
        println "[original: ${str}, encrypted: ${encryptedResult}, decryptedResult: ${decryptedResult}]"

      then: "Then"
        str == decryptedResult
    }


}
