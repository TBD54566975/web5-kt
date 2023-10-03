package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK

public interface KeyManager {
  /**
   * generates and stores a private key based on the arguments provided.
   * @return an alias that can be used to reference the key
   */
  public fun generatePrivateKey(algorithm: Algorithm, curve: Curve? = null, options: KeyGenOptions? = null): String
  public fun getPublicKey(keyAlias: String): JWK

  public fun sign(keyAlias: String, payload: Payload)
}