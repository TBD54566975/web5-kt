package web5.sdk.dids.didcore

import com.nimbusds.jose.jwk.JWK

public class VerificationMethod(
  public val id: String,
  public val type: String,
  public val controller: String,
  public val publicKeyJwk: JWK? = null
) {
  public fun isType(type: String): Boolean {
    return type == this.type
  }

  public companion object Builder {
    private var id: String? = null
    private var type: String? = null
    private var controller: String? = null
    private var publicKeyJwk: JWK? = null


    public fun id(id: String): Builder = apply { this.id = id }
    public fun type(type: String): Builder = apply { this.type = type }
    public fun controller(controller: String): Builder = apply { this.controller = controller }
    public fun publicKeyJwk(publicKeyJwk: JWK): Builder = apply { this.publicKeyJwk = publicKeyJwk }


    public fun build(): VerificationMethod {
      val localId = id ?: throw IllegalStateException("ID is required")
      val localType = type ?: throw IllegalStateException("Type is required")
      val localController = controller ?: throw IllegalStateException("Controller is required")
      val localJwk = publicKeyJwk ?: throw java.lang.IllegalStateException("PublicKeyJwk is required")
      return VerificationMethod(localId, localType, localController, localJwk)
    }

    public fun builder(): Builder {
      return Builder
    }
  }
}
