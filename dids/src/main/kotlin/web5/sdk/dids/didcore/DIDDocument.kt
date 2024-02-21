package web5.sdk.dids.didcore

import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.jose.jwk.JWK
import java.net.URI


/**
 * Document represents a set of data describing the DID subject including mechanisms such as:
 * - cryptographic public keys - used to authenticate itself and prove
 *   association with the DID
 * - services - means of communicating or interacting with the DID subject or
 *   associated entities via one or more service endpoints.
 * Examples include discovery services, agent services, social networking services, file storage services,
 * and verifiable credential repository services.
 * A DID Document can be retrieved by resolving a DID URI.
 *
 * @property id the DID URI for a particular DID subject, expressed using the id property in the DID document.
 * @property context a URI that defines the schema version used in the document.
 * @property alsoKnownAs AlsoKnownAs can contain multiple identifiers for different purposes,
 *           or at different times for the same DID subject. The assertion that two or more DIDs
 *           (or other types of URI) refer to the same DID subject can be made using the alsoKnownAs property.
 * @property controller defines an entity that is authorized to make changes to a DID document.
 * 	         The process of authorizing a DID controller is defined by the DID method.
 * 	         It can be a string or a list of strings.
 * @property verificationMethod a list of cryptographic public keys, which can be used to authenticate or authorize
 * 	         interactions with the DID subject or associated parties.
 * @property service expresses ways of communicating with the DID subject or associated entities.
 * 	         A service can be any type of service the DID subject wants to advertise.
 * @property assertionMethod used to specify how the DID subject is expected to express claims,
 * 	         such as for the purposes of issuing a Verifiable Credential.
 * @property authentication specifies how the DID subject is expected to be authenticated,
 * 	         for purposes such as logging into a website or engaging in any sort of challenge-response protocol.
 * @property keyAgreement specifies how an entity can generate encryption material to transmit confidential
 * 	         information intended for the DID subject, such as for establishing a secure communication channel.
 * @property capabilityDelegation specifies a mechanism used by the DID subject to delegate a
 * 	         cryptographic capability to another party, such as delegating the authority to access a specific HTTP API.
 * @property capabilityInvocation specifies a verification method used by the DID subject to invoke a
 * 	         cryptographic capability, such as the authorization to update the DID Document.
 */
public class DIDDocument(
  public val id: String,
  @JsonProperty("@context")
  public val context: String? = null,
  alsoKnownAs: List<String> = emptyList(),
  controller: List<String> = emptyList(),
  verificationMethod: List<VerificationMethod> = emptyList(),
  service: List<Service> = emptyList(),
  assertionMethod: List<String> = emptyList(),
  authentication: List<String> = emptyList(),
  keyAgreement: List<String> = emptyList(),
  capabilityDelegation: List<String> = emptyList(),
  capabilityInvocation: List<String> = emptyList()
) {

  public val services: List<Service>? = null
  public val assertionMethodVerificationMethods: List<VerificationMethod>? = null
  public val authenticationVerificationMethods: List<VerificationMethod>? = null
  public val capabilityDelegationVerificationMethods: List<VerificationMethod>? = null
  public val capabilityInvocationVerificationMethods: List<VerificationMethod>? = null
  public val keyAgreementVerificationMethods: List<VerificationMethod>? = null

  public val verificationMethods: List<VerificationMethod>? = null
  public val alsoKnownAses: List<URI>? = null
  public val controllers: List<URI>? = null

  public val authenticationVerificationMethodsDereferenced: List<VerificationMethod>? = null
  public val assertionMethodVerificationMethodsDereferenced: List<VerificationMethod>? = null
  public val keyAgreementVerificationMethodsDereferenced: List<VerificationMethod>? = null
  public val capabilityInvocationVerificationMethodsDereferenced: List<VerificationMethod>? = null
  public val capabilityDelegationVerificationMethodsDereferenced: List<VerificationMethod>? = null


  // todo i don't feel great about having these as mutable
  // needed this as mutable to make `this.assertionMethod.add(method.id) work below
  public var verificationMethod: MutableList<VerificationMethod> = verificationMethod.toMutableList()
  public val service: MutableList<Service> = service.toMutableList()
  public val assertionMethod: MutableList<String> = assertionMethod.toMutableList()
  public val authentication: MutableList<String> = authentication.toMutableList()
  public val keyAgreement: MutableList<String> = keyAgreement.toMutableList()
  public val capabilityDelegation: MutableList<String> = capabilityDelegation.toMutableList()
  public val capabilityInvocation: MutableList<String> = capabilityInvocation.toMutableList()

  /**
   * Add verification method adds a verification method to the document.
   * If Purposes are provided, the verification method's ID will be added to the corresponding list of purposes.
   *
   * @param method VerificationMethod to be added to the document
   * @param purposes List of purposes to which the verification method will be added
   */
  public fun addVerificationMethod(method: VerificationMethod, purposes: List<Purpose> = emptyList()) {
    verificationMethod.add(method)
    purposes.forEach { purpose ->
      when (purpose) {
        Purpose.AssertionMethod -> this.assertionMethod.add(method.id)
        Purpose.Authentication -> this.authentication.add(method.id)
        Purpose.KeyAgreement -> this.keyAgreement.add(method.id)
        Purpose.CapabilityDelegation -> this.capabilityDelegation.add(method.id)
        Purpose.CapabilityInvocation -> this.capabilityInvocation.add(method.id)
      }
    }
  }

  /**
   * Select verification method takes a selector that can be used to select a specific verification
   * method from the DID Document. If a selector is not provided, the first verification method
   * is returned
   *
   * The selector can either be an ID, Purpose, or null. If a Purpose is provided, the first verification
   * method in the DID Document that has the provided purpose will be returned.
   *
   * @param selector can either be an ID, Purpose, or null
   * @return VerificationMethod matching the selector criteria
   */
  public fun selectVerificationMethod(selector: VMSelector?): VerificationMethod {
    if (verificationMethod.isEmpty()) throw Exception("No verification methods found")

    if (selector == null) return verificationMethod.first()

    val vmID = when (selector) {
      is Purpose -> {
        val purposeList = when (selector) {
          Purpose.AssertionMethod -> assertionMethod
          Purpose.Authentication -> authentication
          Purpose.CapabilityDelegation -> capabilityDelegation
          Purpose.CapabilityInvocation -> capabilityInvocation
          Purpose.KeyAgreement -> keyAgreement
        }
        purposeList.firstOrNull()
          ?: throw Exception("No verification method found for purpose: ${selector.name}")
      }

      is ID -> selector.value
      else -> throw Exception("Invalid selector type $selector")
    }

    val vm = verificationMethod.find { it.id == vmID } ?: throw Exception("No verification method found for id: $vmID")
    return vm
  }

  public fun addService(service: Service) {
    this.service.add(service)
  }

  public fun getAbsoluteResourceID(id: String): String {
    return if (id.startsWith("#")) "$this.id$id" else id
  }

  // todo fill this method out
  public fun findAssertionMethodById(assertionMethodId: String?): VerificationMethod {
    return VerificationMethod(URI.create("id").toString(), JWK.parse("..."), "JsonWebKey")
  }


  public companion object Builder {
    private var id: String? = null

    private var uri: String? = null
    private var url: String? = null
    private var method: String? = null
    private var params: Map<String, String> = emptyMap()
    private var path: String? = null
    private var query: String? = null
    private var fragment: String? = null
    private var defaultContexts: Boolean? = null
    private var verificationMethods: List<VerificationMethod>? = null
    private var services: List<Service>? = null

    public fun uri(uri: String): Builder = apply { this.uri = uri }
    public fun url(url: String): Builder = apply { this.url = url }
    public fun method(method: String): Builder = apply { this.method = method }
    public fun id(id: String): Builder = apply { this.id = id }
    public fun params(params: Map<String, String>): Builder = apply { this.params = params }
    public fun path(path: String?): Builder = apply { this.path = path }
    public fun query(query: String?): Builder = apply { this.query = query }
    public fun fragment(fragment: String?): Builder = apply { this.fragment = fragment }


    public fun controllers(map: List<URI>) {

    }

    public fun alsoKnownAses(map: List<URI>) {

    }

    public fun defaultContexts(defaultContexts: Boolean): Builder = apply { this.defaultContexts = defaultContexts }
    public fun verificationMethods(verificationMethods: List<VerificationMethod>): Builder = apply {
      this.verificationMethods = verificationMethods
    }

    public fun services(services: List<Service>?): Builder = apply { this.services = services }


    public fun assertionMethodVerificationMethods(verificationMethods: MutableList<VerificationMethod>?): Builder = apply {

    }

    public fun authenticationVerificationMethods(verificationMethods: MutableList<VerificationMethod>?): Builder = apply {

    }

    public fun keyAgreementVerificationMethods(verificationMethods: MutableList<VerificationMethod>?): Builder = apply {

    }

    public fun capabilityDelegationVerificationMethods(verificationMethods: MutableList<VerificationMethod>?): Builder = apply { }


    public fun capabilityInvocationVerificationMethods(verificationMethods: MutableList<VerificationMethod>?): Builder = apply {

    }

    public fun verificationMethod(verificationMethod: VerificationMethod): Builder = apply { }

    public fun assertionMethodVerificationMethod(verificationMethodRef: VerificationMethod): Builder = apply {}

    public fun authenticationVerificationMethod(verificationMethodRef: VerificationMethod): Builder = apply {}

    public fun capabilityInvocationVerificationMethod(verificationMethodRef: VerificationMethod): Builder = apply {}

    public fun keyAgreementVerificationMethod(verificationMethodRef: VerificationMethod): Builder = apply {}

    public fun contexts(mutableListOf: MutableList<URI>): Builder = apply {}

    // todo not sure which fields are required and which are not
    public fun build(): DIDDocument {
      val localId = id ?: throw IllegalStateException("ID is required")
      return DIDDocument(localId)
    }

    public fun builder(): Builder {
      return Builder

    }


  }

}

