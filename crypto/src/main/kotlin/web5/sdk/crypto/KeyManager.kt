package web5.sdk.crypto

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK

public interface KeyManager {
  public fun generatePrivateKey(curve: Curve): String

  public fun generatePrivateKey(curve: Curve, options: GenerateOptions): String

  public fun getPublicKey(alias: String): ByteArray
  public fun getPublicKeyJwk(alias: String): JWK
}