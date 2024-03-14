package web5.sdk.dids.methods.util

import web5.sdk.common.Json
import web5.sdk.crypto.jwk.Jwk
import java.io.File


fun readKey(pathname: String): Jwk {
  return Json.parse<Jwk>(
    File(pathname).readText()
  )
}