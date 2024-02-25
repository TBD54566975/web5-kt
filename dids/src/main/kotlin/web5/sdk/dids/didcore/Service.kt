package web5.sdk.dids.didcore

/**
 * Service is used in DID documents to express ways of communicating with
 * the DID subject or associated entities.
 * A service can be any type of service the DID subject wants to advertise.
 *
 * @property id is the value of the id property and MUST be a URI conforming to RFC3986.
 * 	         A conforming producer MUST NOT produce multiple service entries with
 * 	         the same id. A conforming consumer MUST produce an error if it detects
 * 	         multiple service entries with the same id.
 * @property type is an example of registered types which can be found
 * 	         here: https://www.w3.org/TR/did-spec-registries/#service-types
 * @property serviceEndpoint is a network address, such as an HTTP URL, at which services
 * 	         operate on behalf of a DID subject.
 */
public class Service(
  public val id: String,
  public val type: String,
  public val serviceEndpoint: List<String>
) {

  public companion object Builder {
    private var id: String? = null
    private var type: String? = null
    private var serviceEndpoint: List<String>? = null


    public fun id(id: String): Builder = apply { this.id = id }
    public fun type(type: String): Builder = apply { this.type = type }
    public fun serviceEndpoint(serviceEndpoint: List<String>?): Builder = apply {
      this.serviceEndpoint = serviceEndpoint
    }

    public fun build(): Service {
      val localId = id ?: throw IllegalStateException("ID is required")
      val localType = type ?: throw IllegalStateException("Type is required")
      val localServiceEndpoint = serviceEndpoint ?: throw IllegalStateException("ServiceEndpoint is required")
      return Service(localId, localType, localServiceEndpoint)
    }

    public fun builder(): Builder {
      return Builder

    }
  }
}