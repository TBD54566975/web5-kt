package web5.sdk.dids.didcore

import com.fasterxml.jackson.annotation.JsonProperty
import java.security.SignatureException

/**
 * DIDDocument represents a set of data describing the DID subject including mechanisms such as:
 * - cryptographic public keys - used to authenticate itself and prove association with the DID
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
  public val alsoKnownAs: List<String>? = null,
  public val controller: List<String>? = null,
  public val verificationMethod: List<VerificationMethod>? = null,
  public val service: List<Service>? = null,
  public val assertionMethod: List<String>? = null,
  public val authentication: List<String>? = null,
  public val keyAgreement: List<String>? = null,
  public val capabilityDelegation: List<String>? = null,
  public val capabilityInvocation: List<String>? = null
) {

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
    if (verificationMethod.isNullOrEmpty()) throw Exception("No verification methods found")

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
        purposeList?.firstOrNull()
          ?: throw Exception("No verification method found for purpose: ${selector.name}")
      }

      is ID -> selector.value
      else -> throw Exception("Invalid selector type $selector")
    }

    val vm = this.verificationMethod.find { it.id == vmID }
      ?: throw Exception("No verification method found for id: $vmID")
    return vm
  }

  /**
   * GetAbsoluteResourceID returns a fully qualified ID for a document resource (e.g. service, verification method)
   * Document Resource IDs are allowed to be relative DID URLs as a means to reduce storage size of DID Documents.
   * More info here: https://www.w3.org/TR/did-core/#relative-did-urls
   *
   * @param id of the resource
   * @return fully qualified ID for a document resource
   */
  public fun getAbsoluteResourceID(id: String): String {
    return if (id.startsWith("#")) "${this.id}$id" else id
  }

  /**
   * Finds the first available assertion method from the [DIDDocument]. When [assertionMethodId]
   * is null, the function will return the first available assertion method.
   *
   * @param assertionMethodId The ID of the assertion method to be found
   * @return VerificationMethod with purpose of Assertion
   */
  @JvmOverloads
  public fun findAssertionMethodById(assertionMethodId: String? = null): VerificationMethod {
    require(!assertionMethod.isNullOrEmpty()) {
      throw SignatureException("No assertion methods found in DID document")
    }

    if (assertionMethodId != null) {
      require(assertionMethod.contains(assertionMethodId)) {
        throw SignatureException("assertion method \"$assertionMethodId\" not found in list of assertion methods")
      }
    }

    val assertionMethod: VerificationMethod =
      verificationMethod
        ?.find {
          it.id == (assertionMethodId ?: assertionMethod.first())
        }
        ?: throw SignatureException("assertion method \"$assertionMethodId\" not found")

    return assertionMethod
  }

  /**
   * Builder object to build a DIDDocument.
   */
  public class Builder {

    private var id: String? = null
    private var context: String? = null
    private var alsoKnownAs: List<String>? = null
    private var controller: List<String>? = null

    private var verificationMethod: MutableList<VerificationMethod>? = null
    private var service: List<Service>? = null

    private var assertionMethod: MutableList<String>? = null
    private var authenticationMethod: MutableList<String>? = null
    private var keyAgreementMethod: MutableList<String>? = null
    private var capabilityDelegationMethod: MutableList<String>? = null
    private var capabilityInvocationMethod: MutableList<String>? = null

    /**
     * Adds Id to the DIDDocument.
     *
     * @param id of the DIDDocument
     * @return Builder object
     */
    public fun id(id: String): Builder = apply { this.id = id }

    /**
     * Adds Context to the DIDDocument.
     *
     * @param context of the DIDDocument
     * @return Builder object
     */
    public fun context(context: String): Builder = apply {
      this.context = context
    }

    /**
     * Adds Controllers.
     *
     * @param controllers to be added to DIDDocument
     * @return Builder object
     */
    public fun controllers(controllers: List<String>): Builder = apply { this.controller = controllers }

    /**
     * Adds AlsoknownAses.
     *
     * @param alsoKnownAses to be added to DIDDocument
     * @return Builder object
     */
    public fun alsoKnownAses(alsoKnownAses: List<String>): Builder = apply { this.alsoKnownAs = alsoKnownAses }

    /**
     * Adds Services.
     *
     * @param services to be added to DIDDocument
     * @return Builder object
     */
    public fun services(services: List<Service>?): Builder = apply { this.service = services }

    /**
     * Add verification method adds a verification method to the document.
     * If Purposes are provided, the verification method's ID will be added to the corresponding list of purposes.
     *
     * @param method VerificationMethod to be added to the document
     * @param purposes List of purposes to which the verification method will be added
     */
    @JvmOverloads
    public fun verificationMethodForPurposes(
      method: VerificationMethod,
      purposes: List<Purpose> = emptyList()): Builder =
      apply {
        this.verificationMethod = (this.verificationMethod ?: mutableListOf()).apply { add(method) }
        purposes.forEach { purpose ->
          when (purpose) {
            Purpose.AssertionMethod -> this.assertionMethod =
              (this.assertionMethod ?: mutableListOf()).apply { add(method.id) }

            Purpose.Authentication -> this.authenticationMethod =
              (this.authenticationMethod ?: mutableListOf()).apply { add(method.id) }

            Purpose.KeyAgreement -> this.keyAgreementMethod =
              (this.keyAgreementMethod ?: mutableListOf()).apply { add(method.id) }

            Purpose.CapabilityDelegation -> this.capabilityDelegationMethod =
              (this.capabilityDelegationMethod ?: mutableListOf()).apply { add(method.id) }

            Purpose.CapabilityInvocation -> this.capabilityInvocationMethod =
              (this.capabilityInvocationMethod ?: mutableListOf()).apply { add(method.id) }
          }
        }
      }

    /**
     * Adds VerificationMethods for a single purpose.
     *
     * @param methods a list of VerificationMethods to be added to the DIDDocument
     * @param purpose a single purpose to be associated with the list of VerificationMethods
     * @return Builder object
     */
    @JvmOverloads
    public fun verificationMethodsForPurpose(
      methods: MutableList<VerificationMethod>?,
      purpose: Purpose? = null): Builder =
      apply {
        methods?.forEach { method ->
          verificationMethodForPurposes(method, if (purpose != null) listOf(purpose) else emptyList())
        }
      }

    /**
     * Builds DIDDocument after validating the required fields.
     *
     * @return DIDDocument
     */
    public fun build(): DIDDocument {
      check(id != null) { "ID is required" }
      return DIDDocument(
        id!!,
        context,
        alsoKnownAs,
        controller,
        verificationMethod,
        service,
        assertionMethod,
        authenticationMethod,
        keyAgreementMethod,
        capabilityDelegationMethod,
        capabilityInvocationMethod
      )
    }
  }

  override fun toString(): String {
    return "DIDDocument(" +
      "id='$id', " +
      "context='$context', " +
      "alsoKnownAs=$alsoKnownAs, " +
      "controller=$controller, " +
      "verificationMethod=$verificationMethod, " +
      "service=$service, " +
      "assertionMethod=$assertionMethod, " +
      "authentication=$authentication, " +
      "keyAgreement=$keyAgreement, " +
      "capabilityDelegation=$capabilityDelegation, " +
      "capabilityInvocation=$capabilityInvocation)"
  }

}

