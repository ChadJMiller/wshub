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

        println "public key - encoded (${publicKey.encoded})" 
        println "private key - encoded (${privateKey.encoded})" 

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

    void "test encrypt/decrypt RSA - with public/private key manual usage"() {
        println "dave is here"
      given: "Given a key"
        def privateKeyStr = 
'''-----BEGIN PGP PRIVATE KEY BLOCK-----

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
eZnGIgF2UKYrSCfmbAhPKsjgNyqbbmpp5I/4+r8=
=qvJi
-----END PGP PRIVATE KEY BLOCK-----
'''
        def publicKeyStr = 
'''-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFnyR4UBCADLg8uz99L1ujcx48KfRBxomXO8thye4WW3bE5yosAtRbZENoVr
rsiYirzN7nsYLLU8DZPDjzGf3IWQsmqVyO8MAmnV26/s9fDB+zQLE505+gnN8UdK
ZJAyfbP4Eo2j2pm7LXiHWVUORMIl0urJQa8GS88lPk+OFbWj8q3nju0/H4+e4LCS
sme9yX0HJktIokXXAyrs1Zq+BSpwWMCNJqCbbORTs5kQWDiOx0aR9uue9KaXVG/p
Vf53xlmaPLBfadOms+K+CdlBp50viwmBLkimQYH4l/SmEEPh9Wg3hQKlUZtjqPLY
WbNk5JchaWEtvLc0uS2+57qQb1DcfS2NpiP5ABEBAAG0H2FhYWFhIChhYWFhYSkg
PGFhYWFhQGFhYWFhLmNvbT6JAU4EEwEIADgWIQSDXnw7VVL+RdfY4HhHd0u6/yl/
dgUCWfJHhQIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRBHd0u6/yl/dqfN
B/4yrMDTbvoCUE/skGokq+fi1+8IZLJFuk/taxOp4ioaM10871IiBlyBYczLdqLG
sFWo8880NaBBMf2JnkThMy58wpv7MNBcqh2KcOAElVxdjPDF9Q+PufEVXH40OOkk
B+1ERVhUwyVAU4pMZyzpjjCr2KzkIOZuOusYIcqFfWm0ySWoAB4WxK1WfaRAgtpf
R8i0pXqub5JYx9M9PArYCc8gvbR02o2jM9lVvvEwRv1jrWNkpG1mtRpG1Hcc7/9d
eYOWt+ghQrj/wxD6I4fTRlYqGgNNQaCbt4mYG7mwso+cGpHcA/pyNVNQFHopKBmP
Pl4PFZWPEZLrt9rSf1QgldyquQENBFnyR4UBCAC/AVKMDFwQX3GTRZLUZmnW5x1e
QVCPznpw1OX2ofv6nUGuZGMw7LGd7IzU3akllrIimtD6Ug0HVEEtcMHCuVIgyU8w
IPvpg1KYj2CrSIlWpXerFZN3cbxAx4FYqwmeMXWM1u2roPaHVpouslB+m7pcem0N
JTPFF1QgYZOXvI8Oqe+eMjVC5bdojed3ZOijRvIcP1ysBBJ2l9xTr7EIphudJgS0
YtvLML6AW9J+vP2GgZov21Cl8tvd+m7z48y1Lg6nY8C5sdwOZr0wdoX6Fz9We+uE
I3iYCq4ZnJkS9qQG8RnFtFyjhT01G4aqvl3qJ68zmKNh4jdoOZvSPlDOyJpbABEB
AAGJATYEGAEIACAWIQSDXnw7VVL+RdfY4HhHd0u6/yl/dgUCWfJHhQIbDAAKCRBH
d0u6/yl/dmIwB/9XAoYyfAngKjenlkofp8ZWkSWwgvXVEf0XjzS4Lu0qFMe1if00
jOFI0qu3P/XcR7+SGn3wsSGfuk8Y3FTFNaRYKDWUYWtGGFtgfY1Jmm+xIKkDD5ee
naTDu7nB1RhxSTZX13nIVCI3LQQiZUT+xCgdGXjQceLgpqOFv0sEveqvjIvOBG6T
J6M/ORqbcQ5toftJsWnKzpy9p6ENJ6kIKDTKPsfYA4FRGwCwQYjHDiRAr981nLSx
ZY+Yw5W4YThU/Uzb/kQ5db6ypmfFgrHhmO7UMYOGtN3OugMrWMvHnTJMYDZNWXmZ
xiIBdlCmK0gn5mwITyrI4Dcqm25qaeSP+Pq/
=8zD8
-----END PGP PUBLIC KEY BLOCK-----
'''
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyStr.encode)
        KeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyStr)

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
