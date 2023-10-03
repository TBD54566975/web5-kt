package web5.sdk.crypto

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve

public fun main() {
  val jwk = Crypto.generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1)
  println(jwk)
}