package web5.sdk.dids.methods.util

import com.nimbusds.jose.jwk.JWK
import java.io.File


fun readKey(pathname: String): JWK {
  return JWK.parse(
    File(pathname).readText()
  )
}