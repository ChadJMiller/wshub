package edu.mnscu.wshub

import edu.mnscu.crypto.CryptoService
import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import spock.lang.Specification

import javax.crypto.spec.SecretKeySpec
import java.security.Key

/**
 * See the API for {@link grails.test.mixin.web.ControllerUnitTestMixin} for usage instructions
 */
@TestFor(HubRestController)
@Mock([edu.mnscu.wshub.AuthenticationFilters, CryptoService])
class HubRestControllerSpec extends Specification {
    static final def MILLIS_PER_MINUTE = 1000 * 60

    def setup() {
    }

    def cleanup() {
    }

    void "test filter authenticates/rejects request appropriately"() {
      when:
        def cryptoService = new CryptoService()
        initRequest(theKey, cryptoService, controller, theMethod, timeOffset, theContentType, theContent, thePassword, theAccessKey)

        //ensure filter is involved
        withFilters(action: "index") {
            controller.index()
        }

      then:
        response.status == expectedResult

      where:
        theKey | thePassword | theAccessKey | timeOffset | theMethod | theContentType | theContent || expectedResult
        //happy path
        grailsApplication.config.mnscu.wshub.shared.hmacsha256.key | grailsApplication.config.mnscu.wshub.shared.password | "somekey" | 0                       | "GET"    | ""                 | ""                 || 200
        grailsApplication.config.mnscu.wshub.shared.hmacsha256.key | grailsApplication.config.mnscu.wshub.shared.password | "somekey" | 0                       | "POST"   | "application/json" | '{"test":"value"}' || 200
        grailsApplication.config.mnscu.wshub.shared.hmacsha256.key | grailsApplication.config.mnscu.wshub.shared.password | "somekey" | 0                       | "DELETE" | ""                 | ''                 || 200
        //bad key
        "StZrpr0QwJ+e3dELYa2pgr8B+QdKVhNOPm6Q0dnyrNA="             | grailsApplication.config.mnscu.wshub.shared.password | "somekey" | 0                       | "GET"    | ""                 | ""                 || 403
        //bad password
        grailsApplication.config.mnscu.wshub.shared.hmacsha256.key | "invalidpassword"                                    | "somekey" | 0                       | "GET"    | ""                 | ""                 || 403
        //invalid time: too far in past
        grailsApplication.config.mnscu.wshub.shared.hmacsha256.key | grailsApplication.config.mnscu.wshub.shared.password | "somekey" | -MILLIS_PER_MINUTE * 11 | "GET"    | ""                 | ""                 || 403
        //invalid time: too far in future
        grailsApplication.config.mnscu.wshub.shared.hmacsha256.key | grailsApplication.config.mnscu.wshub.shared.password | "somekey" | MILLIS_PER_MINUTE * 11  | "GET"    | ""                 | ""                 || 403


    }

    private void initRequest(String keyStr
                             , CryptoService cryptoService
                             , def theController
                             , def httpVerb
                             , def theTimeOffset
                             , def contentType
                             , def content
                             , def sharedPassword
                             , def theAccessKey
    ) {
        Key key = new SecretKeySpec(keyStr.decodeBase64(), 'HmacSHA256')

        //values used in request
        def dateMillis = System.currentTimeMillis() + theTimeOffset
        def contentMd5 = "pretend-md5-hash"
        //assemble the signature
        def signatureStr = httpVerb + dateMillis + contentMd5 + contentType + sharedPassword
        //hash the signature
        def signature = cryptoService.hmacSha256(signatureStr, key)
        //assemble request
        theController.request.content = "hello world".bytes
        theController.request.addHeader("x-mnscuws-signature", signature)
        theController.request.addHeader("x-mnscuws-authorization", "MNSCUWS ${theAccessKey}:${signature}")
        theController.request.addHeader("x-mnscuws-date-time-millis", dateMillis)
        theController.request.addHeader("x-mnscuws-content-hash", contentMd5)
        theController.request.contentType = contentType
        theController.request.method = httpVerb
        theController.request.content = content.bytes
    }
}
