package edu.mnscu.wshub

import javax.crypto.spec.SecretKeySpec
import java.security.Key

class AuthenticationFilters {
    def cryptoService
    static final def MILLIS_PER_MINUTE = 1000*60
    def filters = {
        authenticateRestRequest(controller: '*Rest') {
            before = {
                def signature = request.getHeader('x-mnscuws-signature')
                def httpVerb = request.method
                def dateMillis = request.getHeader('x-mnscuws-date-time-millis')
                def contentMd5 = request.getHeader('x-mnscuws-content-hash')
                def contentType = request.contentType
                def sharedPassword = grailsApplication.config.mnscu.wshub.shared.password
                def signatureStr = httpVerb+dateMillis+contentMd5+contentType+sharedPassword

                //initialize hashing key
                String keyStr = grailsApplication.config.mnscu.wshub.shared.hmacsha256.key
                Key key = new SecretKeySpec(keyStr.decodeBase64(), 'HmacSHA256')

                //compare client's hash result with our own
                if (signature != cryptoService.hmacSha256(signatureStr, key)) {
                    render status: 403, text: "not authorized!"
                    return false
                } else {
                    def nowMillis = System.currentTimeMillis()
                    //should be within +- 10 minutes
                    if (dateMillis.toLong() < nowMillis - (MILLIS_PER_MINUTE*10)
                            || dateMillis.toLong() > nowMillis + (MILLIS_PER_MINUTE*10)) {
                        render status: 403, text: "not authorized (stale)!"
                        return false
                    }
                }

                return true
            }
        }
    }
}
