package web5.sdk.dids

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import foundation.identity.did.DIDDocument
import foundation.identity.did.Service
import foundation.identity.did.VerificationMethod
import io.ktor.client.engine.HttpClientEngine
import org.erwinkok.multiformat.multibase.bases.Base32
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Header
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Section
import org.xbill.DNS.TXTRecord
import web5.sdk.common.Convert
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.KeyManager
import java.net.URI
import java.util.Base64

/**
 * Configuration for [DidDht].
 *
 * @property didDhtGateway The URL of the DID DHT gateway to use.
 * @property engine The HTTP client engine to use for requests.
 */
public class DidDhtConfiguration internal constructor(
  // TODO(gabe) update this with our own node when it's ready
  public var didDhtGateway: String = "https://router.nuh.dev:6881",
  public var engine: HttpClientEngine? = null,
)

/**
 * Specifies options for creating a new "did:dht" Decentralized Identifier (DID).
 * @property verificationMethodsToAdd A list of [JWK]s to add to the DID Document mapped to their purposes
 * as verification methods.
 * @property servicesToAdd A list of [Service]s to add to the DID Document.
 * @property publish Whether to publish the DID Document to the DHT after creation.
 */
public class CreateDidDhtOptions(
  public val verificationMethodsToAdd: Iterable<Pair<JWK, Array<PublicKeyPurpose>>>? = null,
  public val servicesToAdd: Iterable<Service>? = null,
  public val publish: Boolean? = false,
) : CreateDidOptions

/**
 * Provides a specific implementation for creating and resolving "did:dht" method Decentralized Identifiers (DIDs).
 *
 * A "did:dht" DID is a special type of DID that is based on an identity key, but can be extended to contain other
 * keys, services, and other DID Document properties. It relies upon Distributed Hash Table (DHT) provided by the
 * BitTorrent network, and an intermediary layer called Pkarr (Public Key Addressable Records) to store and retrieve
 * the DID Document.
 *
 * @property uri The URI of the "did:dht" which conforms to the DID standard.
 * @property keyManager A [KeyManager] instance utilized to manage the cryptographic keys associated with the DID.
 * @property didDocument The [DIDDocument] associated with the DID, created by the class.
 */
public class DidDht(
  uri: String,
  keyManager: KeyManager,
  public val didDocument: DIDDocument? = null) : Did(uri, keyManager) {

  /**
   * Resolves the current instance's [uri] to a [DidResolutionResult], which contains the DID Document
   * and possible related metadata.
   *
   * @return A [DidResolutionResult] instance containing the DID Document and related context.
   *
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:dht" method.
   */
  public fun resolve(): DidResolutionResult {
    return resolve(this.uri)
  }

  /**
   * Publishes the current instance's [didDocument] to the DHT.
   *
   * @throws [InvalidStatusException] When any of the network requests return an invalid HTTP status code.
   */
  public fun publish() {
    return publish(this.didDocument!!)
  }

  public companion object : DidMethod<DidDht, CreateDidDhtOptions> {
    override val methodName: String = "dht"

    public const val TTL: Long = 7200

    /**
     * Creates a new "did:dht" DID, derived from an initial identity key, and stores the associated private key in the
     * provided [KeyManager].
     *
     * The method-specific identifier of a "did:dht" DID is a z-base-32 encoded public key.
     *
     * **Note**: By default, no additional keys or services are added to the document
     *
     * @param keyManager A [KeyManager] instance where the new key will be stored.
     * @param options Optional parameters ([CreateDidDhtOptions]) to specify additional keys, services, and optional
     * publishing during creation.
     * @return A [DidDht] instance representing the newly created "did:dht" DID.
     */
    override fun create(keyManager: KeyManager, options: CreateDidDhtOptions?): DidDht {
      // TODO(gabe): enforce that provided keys are of supported types according to the did:dht spec
      val opts = options ?: CreateDidDhtOptions()

      // create identity key
      val keyAlias = keyManager.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
      val publicKey = keyManager.getPublicKey(keyAlias)

      // build DID Document
      val id = getDidIdentifier(publicKey)

      // add identity key to relationships map
      val identityVerificationMethod = VerificationMethod.builder()
        .id(URI.create("$id#0"))
        .type("JsonWebKey2020")
        .controller(URI.create(id))
        .publicKeyJwk(publicKey.toPublicJWK().toJSONObject())
        .build()

      // add all other keys to the verificationMethod and relationships arrays
      val relationshipsMap = mutableMapOf<PublicKeyPurpose, MutableList<VerificationMethod>>().apply {
        val identityVerificationMethodRef = VerificationMethod.builder().id(identityVerificationMethod.id).build()
        listOf(
          PublicKeyPurpose.AUTHENTICATION,
          PublicKeyPurpose.ASSERTION_METHOD,
          PublicKeyPurpose.CAPABILITY_DELEGATION,
          PublicKeyPurpose.CAPABILITY_INVOCATION
        ).forEach { purpose ->
          getOrPut(purpose) { mutableListOf() }.add(identityVerificationMethodRef)
        }
      }

      // map to the DID object model's verification methods
      val verificationMethods = (opts.verificationMethodsToAdd?.map { (key, purposes) ->
        VerificationMethod.builder()
          .id(URI.create("$id#${key.keyID}"))
          .type("JsonWebKey2020")
          .controller(URI.create(id))
          .publicKeyJwk(key.toPublicJWK().toJSONObject())
          .build().also { verificationMethod ->
            purposes.forEach { relationship ->
              relationshipsMap.getOrPut(relationship) { mutableListOf() }.add(
                VerificationMethod.builder().id(verificationMethod.id).build()
              )
            }
          }
      } ?: emptyList()) + identityVerificationMethod

      // map to the DID object model's services
      val services = opts.servicesToAdd?.map { service ->
        Service.builder()
          .id(URI.create("$id#${service.id}"))
          .type(service.type)
          .serviceEndpoint(service.serviceEndpoint)
          .build()
      }

      // build DID Document
      val didDocument = DIDDocument.builder()
        .id(URI(id))
        .verificationMethods(verificationMethods)
        .services(services)
        .assertionMethodVerificationMethods(relationshipsMap[PublicKeyPurpose.ASSERTION_METHOD])
        .authenticationVerificationMethods(relationshipsMap[PublicKeyPurpose.AUTHENTICATION])
        .keyAgreementVerificationMethods(relationshipsMap[PublicKeyPurpose.KEY_AGREEMENT])
        .capabilityDelegationVerificationMethods(relationshipsMap[PublicKeyPurpose.CAPABILITY_DELEGATION])
        .capabilityInvocationVerificationMethods(relationshipsMap[PublicKeyPurpose.CAPABILITY_INVOCATION])
        .build()

      return DidDht(id, keyManager, didDocument)
    }

    /**
     * Resolves a "did:dht" DID into a [DidResolutionResult], which contains the DID Document and possible related metadata.
     *
     * This implementation talks to a DID DHT gateway to retrieve the DID Document, which in turn takes the z-base-32
     * encoded identifier public key and uses it to retrieve the DID Document from the DHT. Next, the Pkarr response is
     * parsed, and used to reconstruct the DID Document.
     *
     * @param did The "did:dht" DID that needs to be resolved.
     * @return A [DidResolutionResult] instance containing the DID Document and related context.
     *
     * @throws IllegalArgumentException if the provided DID does not conform to the "did:dht" method.
     */
    override fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
      TODO("Not yet implemented")
    }

    /**
     * Generates the identifier for a did:dht DID given its identity key.
     *
     * @param identityKey the key used to generate the DID's identifier
     */
    public fun getDidIdentifier(identityKey: JWK): String {
      val publicKeyJwk = identityKey.toPublicJWK()
      val publicKeyBytes = Crypto.publicKeyToBytes(publicKeyJwk)
      val zBase32Encoded = Base32.encodeZ(publicKeyBytes)
      return "did:dht:$zBase32Encoded"
    }

    /**
     * Publishes a [DIDDocument] to the DHT.
     *
     * @param didDocument The [DIDDocument] to publish.
     */
    public fun publish(didDocument: DIDDocument) {
      TODO("Not yet implemented")
    }

    public fun toDnsPacket(didDocument: DIDDocument): Message {
      val message = Message(0)
      message.header.setFlag(5) // Set authoritative answer flag

      // map key ids to their verification method ids
      val verificationMethodsById = mutableMapOf<String, String>()

      // track all verification methods and services by their ids
      val verificationMethodIds = mutableListOf<String>()
      val serviceIds = mutableListOf<String>()

      // Add Resource Records for each Verification Method
      if (didDocument.verificationMethods != null) {
        for ((i, verificationMethod) in didDocument.verificationMethods?.withIndex()!!) {
          val publicKeyJwk = JWK.parse(verificationMethod.publicKeyJwk)
          val publicKeyBytes = Crypto.publicKeyToBytes(publicKeyJwk)
          val base64UrlEncodedKey = Base64URL(Convert(publicKeyBytes).toBase64Url(padding = false))

          // record the mapping from key id to verification method id
          val vmId = "k${i}"
          verificationMethodsById[verificationMethod.id.toString()] = vmId

          val keyType: Int = when (publicKeyJwk.algorithm) {
            JWSAlgorithm.EdDSA -> {
              0
            }

            JWSAlgorithm.ES256K -> {
              1
            }

            else -> {
              throw IllegalArgumentException("unsupported algorithm: ${publicKeyJwk.algorithm}")
            }
          }

          val keyRecord = TXTRecord(
            Name("_${vmId}._did."),
            DClass.IN,
            TTL,
            "id=${verificationMethod.id.rawFragment};t=${keyType};k=${base64UrlEncodedKey}"
          )

          // add to the list of verification method ids
          verificationMethodIds.add(vmId)

          // add to the packet
          message.addRecord(keyRecord, Section.ANSWER)
        }
      }

      // Add Resource Records for each Service
      if (didDocument.services != null) {
        for ((i, service) in didDocument.services?.withIndex()!!) {
          val sId = "s${i}"
          val serviceRecord = TXTRecord(
            Name("_${sId}._did."),
            DClass.IN,
            TTL,
            "id=${service.id.rawFragment};t=${service.type};uri=${service.serviceEndpoint}"
          )

          // add to the list of service ids
          serviceIds.add(sId)

          // add to the packet
          message.addRecord(serviceRecord, Section.ANSWER)
        }
      }

      // Construct top-level Resource Record
      val rootRecordText = mutableListOf<String>()
      if (verificationMethodIds.size > 0 ) {
        rootRecordText.add("vm=${verificationMethodIds.joinToString(",")}")
      }
      if (serviceIds.size > 0) {
        rootRecordText.add("svc=${serviceIds.joinToString(",")}")
      }

      // Add top-level Resource Record for Verification Relationships
      val authIds =
        didDocument.authenticationVerificationMethodsDereferenced?.map { verificationMethodsById[it.id.toString()] }?.joinToString(",")
      if (authIds != null) {
        rootRecordText.add("auth=${authIds}")
      }

      val assertionIds =
        didDocument.assertionMethodVerificationMethodsDereferenced?.map { verificationMethodsById[it.id.toString()] }?.joinToString(",")
      if (assertionIds != null) {
        rootRecordText.add("asm=${assertionIds}")
      }

      val keyAgreementIds =
        didDocument.keyAgreementVerificationMethodsDereferenced?.map { verificationMethodsById[it.id.toString()] }?.joinToString(",")
      if (keyAgreementIds != null) {
        rootRecordText.add("agm=${keyAgreementIds}")
      }

      val capabilityInvocationIds =
        didDocument.capabilityInvocationVerificationMethodsDereferenced?.map { verificationMethodsById[it.id.toString()] }?.joinToString(",")
      if (capabilityInvocationIds != null) {
        rootRecordText.add("inv=${capabilityInvocationIds}")
      }

      val capabilityDelegationIds =
        didDocument.capabilityDelegationVerificationMethodsDereferenced?.map { verificationMethodsById[it.id.toString()] }?.joinToString(",")
      if (capabilityDelegationIds != null) {
        rootRecordText.add("del=${capabilityDelegationIds}")
      }

      val rootRecord = TXTRecord(
        Name("_did."),
        DClass.IN,
        TTL,
        rootRecordText.joinToString(";")
      )
      message.addRecord(rootRecord, Section.ANSWER)

      return message
    }

    private fun fromDnsPacket(message: Message): DIDDocument {
      TODO("Not yet implemented")
    }
  }

}