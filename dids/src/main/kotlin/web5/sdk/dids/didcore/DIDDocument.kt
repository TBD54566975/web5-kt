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
  public val alsoKnownAs: List<String> = emptyList(),
  public val controller: List<String> = emptyList(),
  public val verificationMethod: List<VerificationMethod> = listOf(),
  public val service: List<Service> = listOf(),
  public val assertionMethod: List<String> = listOf(),
  public val authentication: List<String> = listOf(),
  public val keyAgreement: List<String> = listOf(),
  public val capabilityDelegation: List<String> = listOf(),
  public val capabilityInvocation: List<String> = listOf()
) {

  // todo what are these for? diddhtapi#toDnsPacket asks for these
  public val authenticationVerificationMethodsDereferenced: List<VerificationMethod>? = null
  public val assertionMethodVerificationMethodsDereferenced: List<VerificationMethod>? = null
  public val keyAgreementVerificationMethodsDereferenced: List<VerificationMethod>? = null
  public val capabilityInvocationVerificationMethodsDereferenced: List<VerificationMethod>? = null
  public val capabilityDelegationVerificationMethodsDereferenced: List<VerificationMethod>? = null

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

    val vm = this.verificationMethod.find { it.id == vmID }
      ?: throw Exception("No verification method found for id: $vmID")
    return vm
  }

  public fun getAbsoluteResourceID(id: String): String {
    return if (id.startsWith("#")) "$this.id$id" else id
  }

  /**
   * Finds the first available assertion method from the [DIDDocument]. When [assertionMethodId]
   * is null, the function will return the first available assertion method.
   */
  public fun findAssertionMethodById(assertionMethodId: String? = null): VerificationMethod {
    require(!assertionMethodVerificationMethodsDereferenced.isNullOrEmpty()) {
      throw SignatureException("No assertion methods found in DID document")
    }

    val assertionMethod: VerificationMethod = when {
      assertionMethodId != null -> assertionMethodVerificationMethodsDereferenced.find {
        it.id == assertionMethodId
      }

      else -> assertionMethodVerificationMethodsDereferenced.firstOrNull()
    } ?: throw SignatureException("assertion method \"$assertionMethodId\" not found")
    return assertionMethod
  }

  public companion object Builder {

    private var id: String? = null
    private var context: String? = null
    private var alsoKnownAs: List<String> = emptyList()
    private var controller: List<String> = emptyList()

    private var verificationMethod: MutableList<VerificationMethod> = mutableListOf()
    private var service: MutableList<Service>? = mutableListOf()

    private var assertionMethod: MutableList<String>? = mutableListOf()
    private var authenticationMethod: MutableList<String>? = mutableListOf()
    private var keyAgreementMethod: MutableList<String>? = mutableListOf()
    private var capabilityDelegationMethod: MutableList<String>? = mutableListOf()
    private var capabilityInvocationMethod: MutableList<String>? = mutableListOf()

    public fun id(id: String): Builder = apply { this.id = id }
    public fun context(context: String): Builder = apply {
      this.context = context
    }

    public fun controllers(controllers: List<String>): Builder = apply { this.controller = controllers }
    public fun alsoKnownAses(alsoKnownAses: List<String>): Builder = apply { this.alsoKnownAs = alsoKnownAses }

    /**
     * Add verification method adds a verification method to the document.
     * If Purposes are provided, the verification method's ID will be added to the corresponding list of purposes.
     *
     * @param method VerificationMethod to be added to the document
     * @param purposes List of purposes to which the verification method will be added
     */
    // todo fix terrible name
    public fun verificationMethodForPurposes(method: VerificationMethod, purposes: List<Purpose> = emptyList()): Builder =
      apply {
        this.verificationMethod.add(method)
        purposes.forEach { purpose ->
          when (purpose) {
            Purpose.AssertionMethod -> this.assertionMethod?.add(method.id)
            Purpose.Authentication -> this.authenticationMethod?.add(method.id)
            Purpose.KeyAgreement -> this.keyAgreementMethod?.add(method.id)
            Purpose.CapabilityDelegation -> this.capabilityDelegationMethod?.add(method.id)
            Purpose.CapabilityInvocation -> this.capabilityInvocationMethod?.add(method.id)
          }
        }
      }

    // todo fix terrible name
    public fun verificationMethodsForPurpose(methods: MutableList<VerificationMethod>?, purpose: Purpose): Builder =
      apply {
        methods?.forEach { method ->
          verificationMethodForPurposes(method, listOf(purpose))
        }
      }

    public fun services(services: List<Service>?): Builder = apply { this.service = services?.toMutableList() }

    public fun build(): DIDDocument {
      val localId = id ?: throw IllegalStateException("ID is required")
      return DIDDocument(
        localId,
        context,
        alsoKnownAs,
        controller,
        verificationMethod,
        service!!,
        assertionMethod!!,
        authenticationMethod!!,
        capabilityDelegationMethod!!,
        capabilityInvocationMethod!!
      )
    }

    public fun builder(): Builder {
      return Builder
    }
  }
}

