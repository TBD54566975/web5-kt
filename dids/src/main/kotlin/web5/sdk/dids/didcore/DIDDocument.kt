package web5.sdk.dids.didcore

import com.nimbusds.jose.jwk.JWK

class DIDDocument {
}


public class DidService(
  public val id: String,
  public val type: String,
  public val serviceEndpoint: String
)

public class VerificationMethod(
  public val id: String,
  public val type: String,
  public val controller: String,
  public val publicKeyJwk: JWK? = null
)