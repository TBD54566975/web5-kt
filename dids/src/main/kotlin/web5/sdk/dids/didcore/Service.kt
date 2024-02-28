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
  // todo: is serviceEndpoint a List<String> or String for all DIDs
  // did dht assumes this is List<String> in diddht#fromDnsPacket
  public val serviceEndpoint: List<String>
) {

  /**
   * Builder object to build a Service.
   */
  public class Builder {
    private var id: String? = null
    private var type: String? = null
    private var serviceEndpoint: List<String>? = null


    /**
     * Adds Id to the Service.
     *
     * @param id of the Service
     * @return Builder object
     */
    public fun id(id: String): Builder = apply { this.id = id }

    /**
     * Adds Type to the Service.
     *
     * @param type of the Service
     * @return Builder object
     */
    public fun type(type: String): Builder = apply { this.type = type }

    /**
     * Adds ServiceEndpoint to the Service.
     *
     * @param serviceEndpoint of the Service
     * @return Builder object
     */
    public fun serviceEndpoint(serviceEndpoint: List<String>?): Builder = apply {
      this.serviceEndpoint = serviceEndpoint
    }

    /**
     * Builds Service after validating the required fields.
     *
     * @return Service
     */
    public fun build(): Service {
      check(id != null) { "ID is required" }
      check(type != null) { "Type is required" }
      check(serviceEndpoint != null) { "ServiceEndpoint is required" }
      return Service(id!!, type!!, serviceEndpoint!!)
    }

  }
}