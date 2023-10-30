package web5.sdk.dids

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.DIDDocument
import foundation.identity.did.Service
import foundation.identity.did.VerificationMethod
import foundation.identity.did.VerificationRelationships
import io.ktor.client.engine.HttpClientEngine
import org.erwinkok.multiformat.multibase.bases.Base32
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.KeyManager
import java.net.URI
import java.util.Base64
import kotlin.collections.ArrayList
import kotlin.collections.HashMap

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

public class CreateDidDhtOptions(
  public val verificationMethodsToAdd: Iterable<Pair<JWK, Array<PublicKeyPurpose>>>? = null,
  public val servicesToAdd: Iterable<Service>? = null,
  public val publish: Boolean? = false,
) : CreateDidOptions

public class DidDht(
  uri: String,
  keyManager: KeyManager,
  public val didDocument: DIDDocument? = null) : Did(uri, keyManager) {
  public fun resolve(): DidResolutionResult {
    return resolve(this.uri)
  }

  public companion object : DidMethod<DidDht, CreateDidDhtOptions> {
    override val methodName: String = "dht"

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

    override fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
      TODO("Not yet implemented")
    }

    /**
     * Generates the identifier for a did:dht DID given its identity key
     *
     * @param identityKey the key used to generate the DID's identifier
     */
    public fun getDidIdentifier(identityKey: JWK): String {
      val publicKeyJwk = identityKey.toPublicJWK()
      val publicKeyBytes = Crypto.publicKeyToBytes(publicKeyJwk)
      val zBase32Encoded = Base32.encodeZ(publicKeyBytes)
      return "did:dht:$zBase32Encoded"
    }
  }
  /**
   * Base class for managing DID DHT operations.
   */
//public sealed class DidDhtManager(private val configuration: DidDhtConfiguration) : DidMethod<DidDht, CreateDidDhtOptions> {
//  public fun toDNSPacket(doc: DIDDocument, types: Array<TypeIndex>): Pair<DNSMsg?, Exception?> {
//    val records = ArrayList<DNSRR>()
//    val rootRecord = ArrayList<String>()
//    val keyLookup = HashMap<String, String>()
//
//    // build all key records
//    val vmIDs = ArrayList<String>()
//    for ((i, vm) in doc.verificationMethods.withIndex()) {
//      val recordIdentifier = "k$i"
//      var vmID = vm.id.toString()
//      if (vmID.contains("#")) {
//        vmID = vmID.substring(vmID.lastIndexOf('#') + 1)
//      }
//      keyLookup[vm.id.toString()] = recordIdentifier
//
//      val publicKeyJwk = vm.publicKeyJwk
//      val algorithm = JWK.parse(publicKeyJwk).algorithm.toString()
//      val keyType = when (algorithm) {
//        "EdDSA" -> 0
//        "ES256K" -> 1
//        else -> return Pair(null, Exception("unsupported key type: $algorithm"))
//      }
//
//      // convert the public key to a base64url encoded string
//      val pubKey = vm.publicKeyJWK.toPublicKey() ?: return Pair(null, Exception("conversion error"))
//      val pubKeyBytes = crypto.pubKeyToBytes(pubKey) ?: return Pair(null, Exception("conversion error"))
//      val keyBase64Url = Base64.getUrlEncoder().encodeToString(pubKeyBytes)
//
//      val keyRecord = DNSTXT(
//        hdr = DNSRRHeader(
//          name = "_$recordIdentifier._did.",
//          rrtype = DNSType.TXT,
//          clazz = DNSClass.INET,
//          ttl = 7200
//        ),
//        txt = listOf("id=$vmID,t=$keyType,k=$keyBase64Url")
//      )
//
//      records.add(keyRecord)
//      vmIDs.add(recordIdentifier)
//    }
//    // add verification methods to the root record
//    rootRecord.add("vm=${vmIDs.joinToString(",")}")
//
//    // ... rest of your code, adapted in a similar fashion
//  }
}

public class DNSMsg(public val answer: List<DNSRR>)
public open class DNSRR
public class DNSTXT(public val hdr: DNSRRHeader, public val txt: List<String>) : DNSRR()
public class DNSRRHeader(public val name: String, public val rrtype: DNSType, public val clazz: DNSClass, public val ttl: Int)
public enum class DNSType { TXT }
public enum class DNSClass { INET }
public class TypeIndex