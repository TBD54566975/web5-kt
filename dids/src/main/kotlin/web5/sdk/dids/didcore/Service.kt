package web5.sdk.dids.didcore

import java.net.URI


public class Service(
  // todo id is URI in did-common-java but string in web5-go
  public val id: URI,
  public val type: String,
  public val serviceEndpoint: List<String>? = null
) {

  public companion object Builder {
    private var id: URI? = null
    private var type: String? = null
    private var serviceEndpoint: List<String>? = null


    public fun id(id: URI): Builder = apply { this.id = id }
    public fun type(type: String): Builder = apply { this.type = type }
    public fun serviceEndpoint(serviceEndpoint: List<String>?): Builder = apply {
      this.serviceEndpoint = serviceEndpoint
    }

    // todo not sure which fields are required and which are not
    public fun build(): Service {
      val localId = id ?: throw IllegalStateException("ID is required")
      val localType = type ?: throw IllegalStateException("Type is required")
      return Service(localId, localType)
    }

    public fun builder(): Builder {
      return Builder

    }
  }
}