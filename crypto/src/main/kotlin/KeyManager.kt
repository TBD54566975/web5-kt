package web5.crypto

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK

interface KeyManager {
  fun generatePrivateKey(curve: Curve): String

  fun generatePrivateKey(curve: Curve, options: GenerateOptions): String

  fun getPublicKey(alias: String): ByteArray
  fun getPublicKeyJwk(alias: String): JWK
}