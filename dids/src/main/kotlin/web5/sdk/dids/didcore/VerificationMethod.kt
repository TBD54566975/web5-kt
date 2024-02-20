package web5.sdk.dids.didcore

import com.nimbusds.jose.jwk.JWK
import java.net.URI


public class VerificationMethod(
  // todo id is URI in did-common-java but string in web5-go
  public val id: URI,
  public val publicKeyJwk: JWK? = null,
  public val type: String? = null,
  public val controller: String? = null
) {
  public fun isType(type: String): Boolean {
    return type == this.type
  }

  public companion object Builder {
    private var id: URI? = null
    private var type: String? = null
    private var controller: URI? = null
    private var publicKeyJwk: JWK? = null


    public fun id(id: URI): Builder = apply { this.id = id }
    public fun type(type: String): Builder = apply { this.type = type }
    public fun controller(controller: URI): Builder = apply { this.controller = controller }
    public fun publicKeyJwk(publicKeyJwk: JWK): Builder = apply { this.publicKeyJwk = publicKeyJwk }


    // todo not sure which fields are required and which are not
    public fun build(): VerificationMethod {
      val localId = id ?: throw IllegalStateException("ID is required")
      val locakJwk = publicKeyJwk ?: throw java.lang.IllegalStateException("publicKeyJwk is required")
      return VerificationMethod(localId, locakJwk)
    }

    public fun builder(): Builder {
      return Builder

    }


  }
}
