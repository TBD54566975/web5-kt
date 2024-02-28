package web5.sdk.dids.methods.dht

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import org.xbill.DNS.DClass
import org.xbill.DNS.Message
import org.xbill.DNS.Name
import org.xbill.DNS.Section
import org.xbill.DNS.TXTRecord
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.common.ZBase32
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.Ed25519
import web5.sdk.crypto.KeyManager
import web5.sdk.crypto.Secp256k1
import web5.sdk.dids.CreateDidOptions
import web5.sdk.dids.Did
import web5.sdk.dids.DidMethod
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.ResolutionError
import web5.sdk.dids.ResolveDidOptions
import web5.sdk.dids.didcore.DidUri
import web5.sdk.dids.didcore.DIDDocument
import web5.sdk.dids.didcore.DidDocumentMetadata
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.didcore.Service
import web5.sdk.dids.didcore.VerificationMethod
import web5.sdk.dids.exceptions.InvalidIdentifierException
import web5.sdk.dids.exceptions.InvalidIdentifierSizeException
import web5.sdk.dids.exceptions.InvalidMethodNameException
import web5.sdk.dids.exceptions.PkarrRecordNotFoundException
import web5.sdk.dids.exceptions.PublicKeyJwkMissingException
import web5.sdk.dids.validateKeyMaterialInsideKeyManager
import java.net.URI

/**
 * Configuration for the [DidDhtApi].
 *
 * @property gateway The DID DHT gateway URL.
 * @property engine The engine to use. When absent, a new one will be created from the [OkHttp] factory.
 */
public class DidDhtConfiguration internal constructor(
  public val gateway: String = "https://diddht.tbddev.org",
  public var engine: HttpClientEngine = OkHttp.create {},
)

/**
 * Type indexing types as per https://tbd54566975.github.io/did-dht-method/#type-indexing
 */
public enum class DidDhtTypeIndexing(public val index: Int) {
  Organization(1),
  Government(2),
  Corporation(3),
  LocalBusiness(4),
  SoftwarePackage(5),
  WebApp(6),
  FinancialInstitution(7);

  public companion object {

    /**
     * Returns the [DidDhtTypeIndexing] for the given [value], or null if not found.
     */
    public fun fromInt(value: Int): DidDhtTypeIndexing? = entries.find { it.index == value }
  }
}

/**
 * Returns a [DidDhtApi] after applying [configurationBlock] on the default [DidDhtConfiguration].
 */
public fun DidDhtApi(configurationBlock: DidDhtConfiguration.() -> Unit): DidDhtApi {
  val conf = DidDhtConfiguration().apply(configurationBlock)
  return DidDhtApiImpl(conf)
}

/** [DidDhtApi] is sealed, so we provide an impl so the constructor can be called. */
private class DidDhtApiImpl(configuration: DidDhtConfiguration) : DidDhtApi(configuration)

/**
 * Specifies options for creating a new "did:dht" Decentralized Identifier (DID).
 * @property verificationMethods A list of [JWK]s to add to the DID Document mapped to their purposes
 * as verification methods, and an optional controller for the verification method.
 * @property services A list of [Service]s to add to the DID Document.
 * @property publish Whether to publish the DID Document to the DHT after creation.
 * @property controllers A list of controller DIDs to add to the DID Document.
 * @property alsoKnownAses A list of also known as identifiers to add to the DID Document.
 */
public class CreateDidDhtOptions(
  public val verificationMethods: Iterable<Triple<JWK, List<Purpose>, String?>>? = null,
  public val services: Iterable<Service>? = null,
  public val publish: Boolean = true,
  public val controllers: Iterable<String>? = null,
  public val alsoKnownAses: Iterable<String>? = null,
) : CreateDidOptions

private const val PROPERTY_SEPARATOR = ";"

private const val ARRAY_SEPARATOR = ","

private val logger = KotlinLogging.logger {}

/**
 * Base class for managing DID DHT operations. Uses the given [DidDhtConfiguration].
 */
public sealed class DidDhtApi(configuration: DidDhtConfiguration) : DidMethod<DidDht, CreateDidDhtOptions> {

  private val engine: HttpClientEngine = configuration.engine
  private val dhtClient = DhtClient(configuration.gateway, engine)
  private val ttl: Long = 7200

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
    val keyAlias = keyManager.generatePrivateKey(AlgorithmId.Ed25519)
    val publicKey = keyManager.getPublicKey(keyAlias)

    // build DID Document
    val id = DidDht.getDidIdentifier(publicKey)

    // map to the DID object model's services
    val services = opts.services?.map { service ->
      requireNotNull(service.id) { "Service id cannot be null" }
      requireNotNull(service.type) { "Service type cannot be null" }
      requireNotNull(service.serviceEndpoint) { "Service serviceEndpoint cannot be null" }

      Service(
        id = URI.create("$id#${service.id}").toString(),
        type = service.type,
        serviceEndpoint = service.serviceEndpoint
      )
    }

    // build DID Document
    val didDocumentBuilder = DIDDocument.Builder()
      .id(id)
      .services(services)

    opts.controllers?.let { didDocumentBuilder.controllers(it.toList()) }
    opts.alsoKnownAses?.let { didDocumentBuilder.alsoKnownAses(it.toList()) }

    // add identity key to relationships map
    val identityVerificationMethod =
      VerificationMethod(
        id = "$id#0",
        type = "JsonWebKey",
        controller = URI.create(id).toString(),
        publicKeyJwk = publicKey.toPublicJWK()
      )

    didDocumentBuilder.verificationMethodForPurposes(
      identityVerificationMethod,
      listOf(
        Purpose.AssertionMethod,
        Purpose.Authentication,
        Purpose.CapabilityDelegation,
        Purpose.CapabilityInvocation
      )
    )

    opts.verificationMethods?.map { (key, purposes, controller) ->
      VerificationMethod.Builder()
        .id(URI.create("$id#${key.keyID}").toString())
        .type("JsonWebKey")
        .controller(controller ?: id)
        .publicKeyJwk(key.toPublicJWK())
        .build().also { verificationMethod ->
          didDocumentBuilder.verificationMethodForPurposes(verificationMethod, purposes.toList())

        }
    }


    val didDocument = didDocumentBuilder.build()

    // publish to DHT if requested
    if (opts.publish) {
      publish(keyManager, didDocument)
    }

    return DidDht(id, keyManager, didDocument, this)
  }

  /**
   * Resolves a "did:dht" DID into a [DidResolutionResult], which contains the DID Document and possible related
   * metadata.
   *
   * This implementation talks to a DID DHT gateway to retrieve the DID Document, which in turn takes the z-base-32
   * encoded identifier public key and uses it to retrieve the DID Document from the DHT. Next, the Pkarr response is
   * parsed, and used to reconstruct the DID Document.
   *
   * @param did The "did:dht" DID that needs to be resolved.
   * @return A [DidResolutionResult] instance containing the DID Document and related context, including types
   * as part of the [DidDocumentMetadata], if available.
   */
  override fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
    return try {
      resolveInternal(did)
    } catch (e: Exception) {
      logger.warn(e) { "resolving DID $did failed" }
      DidResolutionResult.fromResolutionError(ResolutionError.INTERNAL_ERROR)
    }
  }

  private fun resolveInternal(did: String): DidResolutionResult {
    try {
      validate(did)
    } catch (_: InvalidMethodNameException) {
      return DidResolutionResult.fromResolutionError(ResolutionError.METHOD_NOT_SUPPORTED)
    } catch (_: InvalidIdentifierSizeException) {
      return DidResolutionResult.fromResolutionError(ResolutionError.INVALID_DID)
    } catch (_: InvalidIdentifierException) {
      return DidResolutionResult.fromResolutionError(ResolutionError.INVALID_DID)
    }
    val getId = DidDht.suffix(did)
    val bep44Message = try {
      dhtClient.pkarrGet(getId)
    } catch (_: PkarrRecordNotFoundException) {
      return DidResolutionResult.fromResolutionError(ResolutionError.NOT_FOUND)
    }
    val dnsPacket = DhtClient.parseBep44GetResponse(bep44Message)
    fromDnsPacket(did, dnsPacket).let { (didDocument, types) ->
      return DidResolutionResult(
        didDocument = didDocument,
        didDocumentMetadata = DidDocumentMetadata(types = types.map { it.index })
      )
    }
  }

  /**
   * Publishes a [DIDDocument] to the DHT.
   *
   * @param manager The [KeyManager] instance to use for signing the message.
   * @param didDocument The [DIDDocument] to publish.
   * @param types A list of types to include in the packet.
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:dht" method.
   * @throws Exception if the message is not successfully put to the DHT.
   */
  @JvmOverloads
  public fun publish(manager: KeyManager, didDocument: DIDDocument, types: List<DidDhtTypeIndexing>? = null) {
    validate(didDocument.id)
    val publishId = DidDht.suffix(didDocument.id)

    val dnsPacket = toDnsPacket(didDocument, types)
    val bep44Message = DhtClient.createBep44PutRequest(manager, getIdentityKid(didDocument), dnsPacket)
    dhtClient.pkarrPut(publishId, bep44Message)
  }

  /**
   * Returns the suffix of the DID, which is the last part of the DID's method-specific identifier.
   *
   * @param id The DID to get the suffix of.
   * @return The suffix of the DID [String].
   */
  public fun suffix(id: String): String {
    return id.split(":").last()
  }

  /**
   * Returns the kid of the identity key for a did:dht DID Document.
   *
   * @param didDocument The DID Document to get the kid of.
   * @return The kid of the identity key.
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:dht" method.
   */
  private fun getIdentityKid(didDocument: DIDDocument): String {
    validate(didDocument.id)

    val publicKeyJwk = didDocument.verificationMethod?.first()?.publicKeyJwk
      ?: throw PublicKeyJwkMissingException("publicKeyJwk is null")
    return publicKeyJwk.keyID
  }

  override fun load(uri: String, keyManager: KeyManager): DidDht {
    validateKeyMaterialInsideKeyManager(uri, keyManager)
    validateIdentityKey(uri, keyManager)
    return DidDht(uri, keyManager, null, this)
  }

  internal fun validateIdentityKey(did: String, keyManager: KeyManager) {
    val parsedDidUri = DidUri.parse(did)
    val decodedId = ZBase32.decode(parsedDidUri.id)
    require(decodedId.size == 32) {
      "expected size of decoded identifier ${parsedDidUri.id} to be 32"
    }

    val publicKeyJwk = Ed25519.bytesToPublicKey(decodedId)
    val identityKeyAlias = keyManager.getDeterministicAlias(publicKeyJwk)
    keyManager.getPublicKey(identityKeyAlias)
  }

  /**
   * Generates the identifier for a did:dht DID, given its identity key.
   *
   * @param identityKey the key used to generate the DID's identifier
   */
  internal fun getDidIdentifier(identityKey: JWK): String {
    val publicKeyJwk = identityKey.toPublicJWK()
    val publicKeyBytes = Crypto.publicKeyToBytes(publicKeyJwk)
    val zBase32Encoded = ZBase32.encode(publicKeyBytes)
    return "did:dht:$zBase32Encoded"
  }

  /**
   * Checks whether a given DID identifier conforms to the "did:dht" method. This checks that the DID starts with
   * "did:dht" and that the suffix is a valid z-base-32 encoded public key.
   *
   * @param did The DID to check.
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:dht" method.
   * @throws InvalidMethodNameException if method name is incorrect
   * @throws InvalidIdentifierException if identifier is not z-base-32 encoded
   * @throws InvalidIdentifierException if decoded identifier length is not 32
   */
  internal fun validate(did: String) {
    val parsedDidUri = DidUri.parse(did)
    require(parsedDidUri.method == DidDht.methodName) {
      throw InvalidMethodNameException("expected method to be dht")
    }

    val decodedId = try {
      ZBase32.decode(parsedDidUri.id)
    } catch (e: IllegalArgumentException) {
      throw InvalidIdentifierException("expected method-specific identifier to be z-base-32 encoded", e)
    }

    require(decodedId.size == 32) {
      throw InvalidIdentifierSizeException("expected size of decoded identifier to be 32")
    }
  }

  /**
   * Converts a [DIDDocument] to a DNS packet according to the did:dht spec
   * https://tbd54566975.github.io/did-dht-method/#dids-as-a-dns-packet
   *
   * @param didDocument The [DIDDocument] to convert.
   * @param types A list of types to include in the packet.
   * @return A [Message] instance containing the DNS packet.
   */
  @JvmOverloads
  internal fun toDnsPacket(didDocument: DIDDocument, types: List<DidDhtTypeIndexing>? = null): Message {
    val message = Message(0).apply { header.setFlag(5) } // Set authoritative answer flag

    // Add Resource Records for each Verification Method
    val (verificationMethodIds, verificationMethodsById) = addVerificationMethodRecords(didDocument, message)

    val serviceIds = mutableListOf<String>()
    // Add Resource Records for each Service
    didDocument.service?.forEachIndexed { i, service ->
      val sId = "s$i"
      message.addRecord(
        TXTRecord(
          Name("_$sId._did."),
          DClass.IN,
          ttl,
          listOf(
            "id=${service.id}",
            "t=${service.type}",
            "se=${serviceRecordValue(service)}"
          ).joinToString(PROPERTY_SEPARATOR)
        ), Section.ANSWER
      )
      serviceIds += sId
    }

    didDocument.controller?.let { addControllerRecord(didDocument, message) }
    didDocument.alsoKnownAs?.let { addAlsoKnownAsRecord(didDocument, message) }

    // Construct top-level Resource Record
    val rootRecordText = mutableListOf<String>().apply {
      if (verificationMethodIds.isNotEmpty()) add("vm=${verificationMethodIds.joinToString(ARRAY_SEPARATOR)}")
      if (serviceIds.isNotEmpty()) add("svc=${serviceIds.joinToString(ARRAY_SEPARATOR)}")

      didDocument.authentication?.map {
        verificationMethodsById[it]
      }?.joinToString(ARRAY_SEPARATOR)?.let { add("auth=$it") }

      didDocument.assertionMethod?.map {
        verificationMethodsById[it]
      }?.joinToString(ARRAY_SEPARATOR)?.let { add("asm=$it") }

      didDocument.keyAgreement?.map {
        verificationMethodsById[it]
      }?.joinToString(ARRAY_SEPARATOR)?.let { add("agm=$it") }

      didDocument.capabilityInvocation?.map {
        verificationMethodsById[it]
      }?.joinToString(ARRAY_SEPARATOR)?.let { add("inv=$it") }

      didDocument.capabilityDelegation?.map {
        verificationMethodsById[it]
      }?.joinToString(ARRAY_SEPARATOR)?.let { add("del=$it") }
    }

    message.addRecord(
      TXTRecord(
        Name("_did."), DClass.IN, ttl, rootRecordText.joinToString(PROPERTY_SEPARATOR)
      ), Section.ANSWER
    )

    // if there are types, add a Resource Record for them
    if (types != null) {
      // convert types to integer values
      val typeIndexes = types.map { it.index }
      message.addRecord(
        TXTRecord(
          Name("_typ._did."), DClass.IN, ttl, "id=${typeIndexes.joinToString(ARRAY_SEPARATOR)}"
        ), Section.ANSWER
      )
    }

    return message
  }

  private fun addVerificationMethodRecords(didDocument: DIDDocument, message: Message):
    Pair<List<String>, Map<String, String>> {
    val verificationMethodsById = mutableMapOf<String, String>()
    val verificationMethods = buildList {
      didDocument.verificationMethod?.forEachIndexed { i, verificationMethod ->
        val publicKeyJwk = verificationMethod.publicKeyJwk ?: throw PublicKeyJwkMissingException("publicKeyJwk is null")
        val publicKeyBytes = Crypto.publicKeyToBytes(publicKeyJwk)
        val base64UrlEncodedKey = Convert(publicKeyBytes).toBase64Url(padding = false)
        val verificationMethodId = "k$i"

        verificationMethodsById[verificationMethod.id] = verificationMethodId

        val keyType = when (publicKeyJwk.algorithm) {
          JWSAlgorithm.EdDSA -> 0
          JWSAlgorithm.ES256K -> 1
          JWSAlgorithm.ES256 -> 2
          else -> throw IllegalArgumentException("unsupported algorithm: ${publicKeyJwk.algorithm}")
        }

        message.addRecord(
          TXTRecord(
            Name("_$verificationMethodId._did."),
            DClass.IN,
            ttl,
            buildList {
              add("id=${verificationMethod.id}")
              add("t=$keyType")
              add("k=$base64UrlEncodedKey")
              add("c=${verificationMethod.controller}")
            }.joinToString(PROPERTY_SEPARATOR)
          ), Section.ANSWER
        )

        add(verificationMethodId)
      }
    }
    return Pair(verificationMethods, verificationMethodsById)
  }

  private fun addAlsoKnownAsRecord(didDocument: DIDDocument, message: Message) {
    if (didDocument.alsoKnownAs.isNullOrEmpty()) {
      return
    }
    message.addRecord(
      TXTRecord(
        Name("_aka._did."),
        DClass.IN,
        ttl,
        didDocument.alsoKnownAs.joinToString(PROPERTY_SEPARATOR)
      ), Section.ANSWER
    )
  }

  private fun addControllerRecord(didDocument: DIDDocument, message: Message) {
    message.addRecord(
      TXTRecord(
        Name("_cnt._did."),
        DClass.IN,
        ttl,
        didDocument.controller?.joinToString(PROPERTY_SEPARATOR)
      ), Section.ANSWER
    )
  }

  private fun serviceRecordValue(service: Service): List<String> {
    return service.serviceEndpoint
  }

  /**
   * Converts a DNS packet to a [DIDDocument] according to the did:dht spec
   * https://tbd54566975.github.io/did-dht-method/#dids-as-a-dns-packet
   *
   * @param did The DID that the packet is for.
   * @param msg The [Message] instance containing the DNS packet.
   * @return A [Pair] containing the [DIDDocument] and a list of types.
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:dht" method.
   */
  internal fun fromDnsPacket(did: String, msg: Message): Pair<DIDDocument, List<DidDhtTypeIndexing>> {
    val doc = DIDDocument.Builder().id(did)

    val verificationMethods = mutableListOf<VerificationMethod>()
    val services = mutableListOf<Service>()
    val types = mutableListOf<DidDhtTypeIndexing>()
    val keyLookup = mutableMapOf<String, String>()

    msg.getSection(Section.ANSWER).forEach { rr ->
      when (rr) {
        is TXTRecord -> {
          val name = rr.name.toString()
          when {
            // handle verification methods
            // todo: no guarantee that this block will run first and fill in the keyLookup
            name.startsWith("_k") -> {
              handleVerificationMethods(rr, verificationMethods, did, keyLookup, name, doc)
            }
            // handle services
            name.startsWith("_s") -> {
              val data = parseTxtData(rr.strings.joinToString(ARRAY_SEPARATOR))
              val service = Service.Builder()
                .id("$did#${data["id"]!!}")
                .type(data["t"]!!)
                .serviceEndpoint(data["se"]!!.split(ARRAY_SEPARATOR))
                .build()
              services.add(service)
              doc.services(services)
            }
            // handle type indexing
            name.startsWith("_typ._did.") -> {
              if (rr.strings[0].isNotEmpty() && rr.strings.size == 1) {
                types += rr.strings[0].removePrefix("id=").split(ARRAY_SEPARATOR).map {
                  DidDhtTypeIndexing.fromInt(it.toInt()) ?: throw IllegalArgumentException("invalid type index")
                }
              } else {
                throw IllegalArgumentException("invalid types record")
              }
            }
            // handle root record
            name.startsWith("_did.") -> {
              handleRootRecord(rr, keyLookup, doc, did)
            }
            // handle controller record
            name.startsWith("_cnt._did.") -> {
              handleControllerRecord(rr, doc)
            }
            // handle alsoKnownAs record
            name.startsWith("_aka._did.") -> {
              handleAlsoKnownAsRecord(rr, doc)
            }
          }
        }
      }
    }

    return doc.build() to types
  }

  private fun handleAlsoKnownAsRecord(rr: TXTRecord, doc: DIDDocument.Builder) {
    val data = rr.strings.joinToString("")
    doc.alsoKnownAses(data.split(ARRAY_SEPARATOR))
  }

  private fun handleControllerRecord(rr: TXTRecord, doc: DIDDocument.Builder) {
    val data = rr.strings.joinToString("")
    doc.controllers(data.split(ARRAY_SEPARATOR))
  }

  private fun handleVerificationMethods(
    rr: TXTRecord,
    verificationMethods: MutableList<VerificationMethod>,
    did: String,
    keyLookup: MutableMap<String, String>,
    name: String,
    didDocBuilder: DIDDocument.Builder
  ) {
    val data = parseTxtData(rr.strings.joinToString(""))
    val verificationMethodId = data["id"]!!
    val keyBytes = Convert(data["k"]!!, EncodingFormat.Base64Url).toByteArray()

    // TODO(gabe): support other key types
    val publicKeyJwk = when (data["t"]!!) {
      "0" -> Ed25519.bytesToPublicKey(keyBytes)
      "1" -> Secp256k1.bytesToPublicKey(keyBytes)
      else -> throw IllegalArgumentException("Unknown key type: ${data["t"]}")
    }

    val vmBuilder = VerificationMethod.Builder()
      .id("$did#$verificationMethodId")
      .type("JsonWebKey")
      .publicKeyJwk(publicKeyJwk.toPublicJWK())

    if (data.containsKey("c")) {
      vmBuilder.controller(data["c"]!!)
    } else {
      vmBuilder.controller(
        when (verificationMethodId) {
          "0" -> did
          else -> ""
        }

      )
    }

    val vm = vmBuilder.build()
    verificationMethods.add(vm)
    didDocBuilder.verificationMethodsForPurpose(verificationMethods)

    keyLookup[name.split(".")[0].drop(1)] = "$did#$verificationMethodId"
  }

  private fun handleRootRecord(
    rr: TXTRecord,
    keyLookup: Map<String, String>,
    doc: DIDDocument.Builder,
    did: String
  ) {
    val rootData = rr.strings.joinToString(PROPERTY_SEPARATOR).split(PROPERTY_SEPARATOR)

    val purposeToVerificationMethod = mapOf<String, MutableList<VerificationMethod>>(
      "asm" to mutableListOf(),
      "auth" to mutableListOf(),
      "agm" to mutableListOf(),
      "inv" to mutableListOf(),
      "del" to mutableListOf()
    )

    rootData.forEach { item ->
      val (key, values) = item.split("=")
      val valuesList = values.split(ARRAY_SEPARATOR)

      valuesList.forEach {
        // todo what the heck is my publicJwk???
        val vm = VerificationMethod
          .Builder()
          .id(keyLookup[it]!!)
          .type("JsonWebKey")
          .controller(did)
          .build()
        purposeToVerificationMethod[key]?.add(vm)
      }
    }

    // add verification relationships
    doc.verificationMethodsForPurpose(purposeToVerificationMethod["asm"], Purpose.AssertionMethod)
    doc.verificationMethodsForPurpose(purposeToVerificationMethod["auth"], Purpose.Authentication)
    doc.verificationMethodsForPurpose(purposeToVerificationMethod["agm"], Purpose.KeyAgreement)
    doc.verificationMethodsForPurpose(purposeToVerificationMethod["del"], Purpose.CapabilityDelegation)
    doc.verificationMethodsForPurpose(purposeToVerificationMethod["inv"], Purpose.CapabilityInvocation)
  }

  /**
   * Parses a string of key-value pairs separated by semicolons into a map.
   * @param data The string to parse.
   */
  private fun parseTxtData(data: String): Map<String, String> {
    return data.split(PROPERTY_SEPARATOR).associate {
      val (key, value) = it.split("=")
      key to value
    }
  }
}

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
  uri: String, keyManager: KeyManager,
  public val didDocument: DIDDocument? = null,
  private val didDhtApi: DidDhtApi
) : Did(uri, keyManager) {

  /**
   * Calls [DidDhtApi.create] with the provided [CreateDidDhtOptions] and returns the result.
   */
  public fun create(createDidDhtOptions: CreateDidDhtOptions): DidDht {
    return didDhtApi.create(keyManager, createDidDhtOptions)
  }

  /**
   * Calls [DidDhtApi.resolve] with the provided [ResolveDidOptions] and returns the result.
   */
  public fun resolve(resolveDidOptions: ResolveDidOptions): DidResolutionResult {
    return didDhtApi.resolve(uri, resolveDidOptions)
  }

  /**
   * Calls [DidDhtApi.publish] with the provided [keyManager] and [didDocument].
   */
  public fun publish() {
    didDhtApi.publish(keyManager, didDocument!!)
  }

  /**
   * Calls [DidDht.suffix] with the provided [id] and returns the result.
   */
  @JvmOverloads
  public fun suffix(id: String = this.uri): String {
    return DidDht.suffix(id)
  }

  /**
   * Calls [DidDht.validate] with the provided [did].
   */
  @JvmOverloads
  public fun validate(did: String = this.uri) {
    DidDht.validate(did)
  }

  /**
   * Calls [DidDht.toDnsPacket] with the provided [didDocument] and [types] and returns the result.
   */
  @JvmOverloads
  public fun toDnsPacket(didDocument: DIDDocument, types: List<DidDhtTypeIndexing>? = emptyList()): Message {
    return DidDht.toDnsPacket(didDocument, types)
  }

  /**
   * Calls [DidDht.fromDnsPacket] with the provided [did] and [msg] and returns the result.
   */
  @JvmOverloads
  public fun fromDnsPacket(did: String = this.uri, msg: Message): Pair<DIDDocument, List<DidDhtTypeIndexing>> {
    return DidDht.fromDnsPacket(did, msg)
  }

  /**
   * Default companion object for creating a [DidDhtApi] with a default configuration.
   */
  public companion object Default : DidDhtApi(DidDhtConfiguration())
}