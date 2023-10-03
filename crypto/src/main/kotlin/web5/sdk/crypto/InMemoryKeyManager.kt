package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK

public class InMemoryKeyManager : KeyManager {
  // in-memory keystore. flat k/v map where the key is a keyId.
  private val keyStore: MutableMap<String, JWK> = HashMap()
  override fun generatePrivateKey(algorithm: Algorithm, curve: Curve?, options: KeyGenOptions?): String {
    val jwk = Crypto.generatePrivateKey(algorithm, curve, options)
    keyStore[jwk.keyID] = jwk

    return jwk.keyID
  }

  override fun getPublicKey(keyAlias: String): JWK {
    TODO("Not yet implemented")
  }

  override fun sign(keyAlias: String, payload: Payload) {
    TODO("Not yet implemented")
  }
}