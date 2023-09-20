package web5.crypto

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK

class InMemoryKeyManager {
  val cryptoPrimitives = hashMapOf<Curve, CryptoPrimitive<JWK>>(
    Ed25519.curve to Ed25519,
    Secp256k1.curve to Secp256k1
  )

  fun generateKey(curve: Curve) {}
}