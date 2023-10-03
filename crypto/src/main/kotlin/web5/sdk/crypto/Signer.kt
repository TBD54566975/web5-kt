package web5.sdk.crypto

import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.JWK

public interface SignOptions {
  public val privateKey: JWK
  public val payload: Payload
}

public interface VerifyOptions

public interface Signer {
  public fun sign(privateKey: JWK, payload: Payload, options: SignOptions? = null): String
  public fun verify(options: VerifyOptions? = null)
}