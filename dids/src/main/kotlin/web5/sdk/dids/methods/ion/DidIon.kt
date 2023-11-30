package web5.sdk.dids.methods.ion

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import foundation.identity.did.DID
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.serialization.jackson.jackson
import kotlinx.coroutines.runBlocking
import org.erdtman.jcs.JsonCanonicalizer
import web5.sdk.common.Convert
import web5.sdk.common.Varint
import web5.sdk.crypto.KeyGenOptions
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.CreateDidOptions
import web5.sdk.dids.CreationMetadata
import web5.sdk.dids.Did
import web5.sdk.dids.DidMethod
import web5.sdk.dids.DidResolutionMetadata
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.PublicKeyPurpose
import web5.sdk.dids.ResolveDidOptions
import web5.sdk.dids.methods.ion.models.AddPublicKeysAction
import web5.sdk.dids.methods.ion.models.AddServicesAction
import web5.sdk.dids.methods.ion.models.Commitment
import web5.sdk.dids.methods.ion.models.DeactivateUpdateSignedData
import web5.sdk.dids.methods.ion.models.Delta
import web5.sdk.dids.methods.ion.models.Document
import web5.sdk.dids.methods.ion.models.InitialState
import web5.sdk.dids.methods.ion.models.OperationSuffixDataObject
import web5.sdk.dids.methods.ion.models.PatchAction
import web5.sdk.dids.methods.ion.models.PublicKey
import web5.sdk.dids.methods.ion.models.RecoveryUpdateSignedData
import web5.sdk.dids.methods.ion.models.RemovePublicKeysAction
import web5.sdk.dids.methods.ion.models.RemoveServicesAction
import web5.sdk.dids.methods.ion.models.ReplaceAction
import web5.sdk.dids.methods.ion.models.Reveal
import web5.sdk.dids.methods.ion.models.Service
import web5.sdk.dids.methods.ion.models.SidetreeCreateOperation
import web5.sdk.dids.methods.ion.models.SidetreeDeactivateOperation
import web5.sdk.dids.methods.ion.models.SidetreeRecoverOperation
import web5.sdk.dids.methods.ion.models.SidetreeUpdateOperation
import web5.sdk.dids.methods.ion.models.UpdateOperationSignedData
import web5.sdk.dids.validateKeyMaterialInsideKeyManager
import java.net.URI
import java.security.MessageDigest
import java.util.UUID

private const val operationsPath = "/operations"
private const val identifiersPath = "/identifiers"

private val sha256MultiCodec = Varint.encode(0x12)

/**
 * Configuration for the [DidIonApi].
 *
 * @property ionHost The ION host URL.
 * @property engine The engine to use. When absent, a new one will be created from the [CIO] factory.
 */
public class DidIonConfiguration internal constructor(
  public var ionHost: String = "https://ion.tbddev.org",
  public var engine: HttpClientEngine? = null,
)


/**
 * Returns a [DidIonApi] after applying [configurationBlock] on the default [DidIonConfiguration].
 */
public fun DidIonApi(configurationBlock: DidIonConfiguration.() -> Unit): DidIonApi {
  val conf = DidIonConfiguration().apply(configurationBlock)
  return DidIonApiImpl(conf)
}

/** [DidIonApi] is sealed, so we provide an impl so the constructor can be called. */
private class DidIonApiImpl(configuration: DidIonConfiguration) : DidIonApi(configuration)

/**
 * The options when updating an ION did.
 *
 * @param updateKeyAlias The alias within the key manager that refers to the last update key.
 * @param servicesToAdd The services to add in the did document.
 * @param idsOfServicesToRemove Ids of the services to remove from the did document.
 * @param verificationMethodsToAdd List of specs that will be added to the DID ION document.
 * @param idsOfPublicKeysToRemove Keys to remove from the DID document.
 */
public data class UpdateDidIonOptions(
  val updateKeyAlias: String,
  override val servicesToAdd: Iterable<Service> = emptyList(),
  val idsOfServicesToRemove: Iterable<String> = emptyList(),
  override val verificationMethodsToAdd: Iterable<VerificationMethodSpec> = emptyList(),
  val idsOfPublicKeysToRemove: Iterable<String> = emptyList(),
) : CommonOptions {
  internal fun toPatches(publicKeys: Iterable<PublicKey>): List<PatchAction> {
    fun <T> MutableList<PatchAction>.addIfNotEmpty(iter: Iterable<T>, action: (Iterable<T>) -> PatchAction) {
      iter.takeIf { it.count() != 0 }?.let { this.add(action(it)) }
    }

    return buildList {
      addIfNotEmpty(servicesToAdd, ::AddServicesAction)
      addIfNotEmpty(idsOfServicesToRemove, ::RemoveServicesAction)
      addIfNotEmpty(publicKeys, ::AddPublicKeysAction)
      addIfNotEmpty(idsOfPublicKeysToRemove, ::RemovePublicKeysAction)
    }
  }
}

/**
 * The options when recovering an ION did.
 *
 * @param recoveryKeyAlias is the alias within the keyManager to use when signing. It must match the recovery used with
 *   the last recovery operation.
 * @param verificationMethodsToAdd List of specs that will be added to the DID ION document.
 * @param servicesToAdd When provided, the services will be added to the DID document. Note that for each of the
 * services that should be added, the following must hold:
 *   - The `id` field cannot be over 50 chars and must only use characters from the Base64URL character set.
 *   - The `type` field cannot be over 30 characters.
 *   - The `serviceEndpoint` must be a valid URI.
 */
public class RecoverDidIonOptions(
  public val recoveryKeyAlias: String,
  public override val verificationMethodsToAdd: Iterable<VerificationMethodSpec> = emptyList(),
  public override val servicesToAdd: Iterable<Service> = emptyList(),
) : CommonOptions

/**
 * Options when deactivating an ION did.
 *
 * [recoveryKeyAlias] is the alias within the keyManager to use when signing. It must match the recovery used with the
 * last recovery operation.
 */
public class DeactivateDidIonOptions(public val recoveryKeyAlias: String)


/**
 * Provides a specific implementation for creating and resolving "did:ion" method Decentralized Identifiers (DIDs).
 *
 * A "did:ion" DID is an implementation of the Sidetree protocol that uses Bitcoin as it's anchoring system.
 * Further specifics and technical details are outlined in [the DID Sidetree Spec](https://identity.foundation/sidetree/spec/).
 *
 * @property uri The URI of the "did:ion" which conforms to the DID standard.
 * @property keyManager A [KeyManager] instance utilized to manage the cryptographic keys associated with the DID.
 * @property creationMetadata Metadata related to the creation of a DID. Useful for debugging purposes.
 * @property didIonApi A [DidIonApi] instance utilized to delegate all the calls to an ION node.
 */
public class DidIon(
  uri: String,
  keyManager: KeyManager,
  public val creationMetadata: IonCreationMetadata? = null,
  private val didIonApi: DidIonApi) : Did(uri, keyManager) {

  /**
   * Calls [DidIonApi.update] for this DID.
   */
  public fun update(options: UpdateDidIonOptions): IonUpdateResult = didIonApi.update(keyManager, this.uri, options)

  /**
   * Calls [DidIonApi.recover] for this DID.
   */
  public fun recover(options: RecoverDidIonOptions): IonRecoverResult = didIonApi.recover(keyManager, this.uri, options)

  /**
   * Calls [DidIonApi.deactivate] for this DID.
   */
  public fun deactivate(options: DeactivateDidIonOptions): IonDeactivateResult = didIonApi.deactivate(
    keyManager,
    this.uri,
    options
  )

  /**
   * Calls [DidIonApi.resolve] for this DID.
   */
  public fun resolve(options: ResolveDidOptions?): DidResolutionResult = didIonApi.resolve(uri, options)

  /**
   * Default companion object for creating a [DidIonApi] with a default configuration.
   */
  public companion object Default : DidIonApi(DidIonConfiguration())
}

private const val maxServiceTypeLength = 30

private const val maxIdLength = 50

private const val base64UrlCharsetRegexStr = "^[A-Za-z0-9_-]+$"

private val base64UrlCharsetRegex = base64UrlCharsetRegexStr.toRegex()

/**
 * Base class for managing DID Ion operations. Uses the given [configuration].
 */
public sealed class DidIonApi(
  private val configuration: DidIonConfiguration
) : DidMethod<DidIon, CreateDidIonOptions> {

  private val mapper = jacksonObjectMapper()

  private val operationsEndpoint = configuration.ionHost + operationsPath
  private val identifiersEndpoint = configuration.ionHost + identifiersPath

  private val engine: HttpClientEngine = configuration.engine ?: CIO.create {}

  private val client = HttpClient(engine) {
    install(ContentNegotiation) {
      jackson { mapper }
    }
  }

  override val methodName: String = "ion"

  /**
   * Creates a [DidIon], which includes a DID and it's associated DID Document. In order to ensure the creation
   * works appropriately, the DID is resolved immediately after it's created.
   *
   * Note: [options] must be of type [CreateDidIonOptions].
   * @throws [ResolutionException] When there is an error after resolution.
   * @throws [InvalidStatusException] When any of the network requests return an invalid HTTP status code.
   * @see [DidMethod.create] for details of each parameter.
   */
  override fun create(keyManager: KeyManager, options: CreateDidIonOptions?): DidIon {
    val (createOp, keys) = createOperation(keyManager, options)

    val canonicalizedSuffixData = canonicalized(createOp.suffixData)
    val suffixDataMultihash = multihash(canonicalizedSuffixData)
    val shortFormDidSegment = Convert(suffixDataMultihash).toBase64Url(padding = false)

    val initialState = InitialState(
      suffixData = createOp.suffixData,
      delta = createOp.delta,
    )
    val longFormDidSegment = didUriSegment(initialState)

    val response: HttpResponse = runBlocking {
      client.post(operationsEndpoint) {
        contentType(ContentType.Application.Json)
        setBody(createOp)
      }
    }

    val opBody = runBlocking {
      response.bodyAsText()
    }

    if (response.status.isSuccess()) {
      val shortFormDid = "did:ion:$shortFormDidSegment"
      val longFormDid = "$shortFormDid:$longFormDidSegment"
      val resolutionResult = resolve(longFormDid)

      if (!resolutionResult.didResolutionMetadata?.error.isNullOrEmpty()) {
        throw ResolutionException(
          "error when resolving after creation: ${resolutionResult.didResolutionMetadata?.error}"
        )
      }

      return DidIon(
        resolutionResult.didDocument.id.toString(),
        keyManager,
        IonCreationMetadata(
          createOp,
          shortFormDid,
          longFormDid,
          opBody,
          keys
        ),
        this
      )
    }
    throw InvalidStatusException(response.status.value, "received error response: '$opBody'")
  }

  /**
   * Instantiates a [DidIon] instance from [uri] (which has to start with "did:ion:"), and validates that the
   * associated key material exists in the provided [keyManager].
   *
   * ### Usage Example:
   * ```kotlin
   * val keyManager = InMemoryKeyManager()
   * val did = DidIon.load("did:ion:example", keyManager)
   * ```
   */
  override fun load(uri: String, keyManager: KeyManager): DidIon {
    validateKeyMaterialInsideKeyManager(uri, keyManager)
    // TODO: validate other keys.
    return DidIon(uri, keyManager, null, this)
  }

  private fun canonicalized(data: Any): ByteArray {
    val jsonString = mapper.writeValueAsString(data)
    return JsonCanonicalizer(jsonString).encodedUTF8
  }

  private fun didUriSegment(initialState: InitialState): String {
    val canonicalized = canonicalized(initialState)
    return Convert(canonicalized).toBase64Url(padding = false)
  }

  /**
   * Given a [did], returns the [DidResolutionResult], which is specified in https://w3c-ccg.github.io/did-resolution/#did-resolution-result
   *
   * @throws [InvalidStatusException] When any of the network requests return an invalid HTTP status code.
   */
  override fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
    val didObj = DID.fromString(did)
    require(didObj.methodName == methodName) { throw IllegalArgumentException("expected did:ion") }

    val resp = runBlocking { client.get("$identifiersEndpoint/$didObj") }
    val body = runBlocking { resp.bodyAsText() }
    if (!resp.status.isSuccess()) {
      throw InvalidStatusException(resp.status.value, "resolution error response: '$body'")
    }
    return mapper.readValue(body, DidResolutionResult::class.java)
  }

  /**
   * Updates [did] with the given [options]. The update key must be available in the [keyManager].
   */
  public fun update(keyManager: KeyManager, did: String, options: UpdateDidIonOptions): IonUpdateResult {
    val (updateOp, keyAliases) = createUpdateOperation(keyManager, did, options)
    val response: HttpResponse = runBlocking {
      client.post(operationsEndpoint) {
        contentType(ContentType.Application.Json)
        setBody(updateOp)
      }
    }
    val opBody = runBlocking { response.bodyAsText() }
    if (response.status.isSuccess()) {
      return IonUpdateResult(
        operationsResponseBody = opBody,
        keyAliases = keyAliases,
      )
    }
    throw InvalidStatusException(response.status.value, "received error response: '$opBody'")
  }

  private fun createUpdateOperation(keyManager: KeyManager, did: String, options: UpdateDidIonOptions):
    Pair<SidetreeUpdateOperation, KeyAliases> {
    val parsedDid = DID.fromString(did)
    require(!parsedDid.methodSpecificId.contains(":")) {
      "updating a DID is only allowed for short form dids, but got $did"
    }
    val updatePublicKey = keyManager.getPublicKey(options.updateKeyAlias)

    val newUpdateKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val newUpdatePublicKey = keyManager.getPublicKey(newUpdateKeyAlias)

    val reveal = updatePublicKey.reveal()
    val commitment = newUpdatePublicKey.commitment()

    validateServices(options.servicesToAdd)

    val publicKeysWithAliases = options.verificationMethodsToAdd.toPublicKeys(keyManager)
    val publicKeys = publicKeysWithAliases.map { it.second }
    validateDidDocumentKeys(publicKeys)

    val updateOpDeltaObject = Delta(
      patches = options.toPatches(publicKeys),
      updateCommitment = commitment
    )

    val deltaHash = deltaHash(updateOpDeltaObject)

    val updateOpSignedData = UpdateOperationSignedData(
      updateKey = updatePublicKey,
      deltaHash = deltaHash,
    )
    val signedJwsObject = sign(updateOpSignedData, keyManager, options.updateKeyAlias)

    return Pair(
      SidetreeUpdateOperation(
        type = "update",
        didSuffix = parsedDid.methodSpecificId,
        revealValue = reveal,
        delta = updateOpDeltaObject,
        signedData = signedJwsObject.serialize(false),
      ),
      KeyAliases(
        updateKeyAlias = newUpdateKeyAlias,
        verificationKeyAliases = publicKeysWithAliases.mapNotNull { it.first },
        recoveryKeyAlias = null
      )
    )
  }

  private fun sign(serializableObject: Any, keyManager: KeyManager, signKeyAlias: String): JWSObject {
    val header = JWSHeader.Builder(JWSAlgorithm.ES256K).build()
    val payload = Payload(mapper.writeValueAsString(serializableObject))
    val jwsObject = JWSObject(header, payload)
    val signatureBytes = keyManager.sign(signKeyAlias, jwsObject.signingInput)

    val base64UrlEncodedSignature = Base64URL(Convert(signatureBytes).toBase64Url(padding = false))
    return JWSObject(
      jwsObject.header.toBase64URL(),
      jwsObject.payload.toBase64URL(),
      base64UrlEncodedSignature,
    )
  }

  private fun deltaHash(updateOpDeltaObject: Delta): String {
    val canonicalizedOp = canonicalized(updateOpDeltaObject)
    val opMultihash = multihash(canonicalizedOp)

    return Convert(opMultihash).toBase64Url(padding = false)
  }

  private fun validateDidDocumentKeys(publicKeys: Iterable<PublicKey>) {
    val publicKeyIdSet = HashSet<String>()
    for (publicKey in publicKeys) {
      validateId(publicKey.id)
      if (publicKeyIdSet.contains(publicKey.id)) {
        throw IllegalArgumentException("DID Document key with ID \"${publicKey.id}\" already exists.")
      }
      publicKeyIdSet.add(publicKey.id)

      validatePublicKeyPurposes(publicKey.purposes)
    }
  }

  private fun validatePublicKeyPurposes(purposes: Iterable<PublicKeyPurpose>) {
    val processedPurposes = HashSet<PublicKeyPurpose>()
    for (purpose in purposes) {
      if (processedPurposes.contains(purpose)) {
        throw IllegalArgumentException("Public key purpose \"${purpose.code}\" already specified.")
      }
      processedPurposes.add(purpose)
    }
  }

  internal fun createOperation(keyManager: KeyManager, options: CreateDidIonOptions?)
    : Pair<SidetreeCreateOperation, KeyAliases> {
    val updateKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val updatePublicJwk = keyManager.getPublicKey(updateKeyAlias)

    val publicKeyCommitment = updatePublicJwk.commitment()

    val publicKeysWithAlias = publicKeysWithAliasesToAdd(options, keyManager)
    val publicKeysToAdd = publicKeysWithAlias.map { it.second }
    validateDidDocumentKeys(publicKeysToAdd)

    validateServices(options?.servicesToAdd ?: emptyList())

    val createOperationDelta = Delta(
      patches = options.toPatches(publicKeysToAdd),
      updateCommitment = publicKeyCommitment
    )

    val recoveryKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val recoveryPublicJwk = keyManager.getPublicKey(recoveryKeyAlias)
    val recoveryCommitment = recoveryPublicJwk.commitment()

    val operation: OperationSuffixDataObject =
      createOperationSuffixDataObject(createOperationDelta, recoveryCommitment)

    return Pair(
      SidetreeCreateOperation(
        type = "create",
        suffixData = operation,
        delta = createOperationDelta,
      ),
      KeyAliases(
        updateKeyAlias = updateKeyAlias,
        verificationKeyAliases = publicKeysWithAlias.mapNotNull { it.first },
        recoveryKeyAlias = recoveryKeyAlias
      )
    )
  }

  private fun publicKeysWithAliasesToAdd(options: CommonOptions?, keyManager: KeyManager) =
    if (options == null || options.verificationMethodsToAdd.count() == 0) {
      listOf<VerificationMethodSpec>(
        VerificationMethodCreationParams(
          JWSAlgorithm.ES256K,
          relationships = listOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.ASSERTION_METHOD)
        )
      ).toPublicKeys(keyManager)
    } else {
      options.verificationMethodsToAdd.toPublicKeys(keyManager)
    }

  private fun validateServices(services: Iterable<Service>) = services.forEach {
    validateService(it)
  }

  private fun validateService(service: Service) {
    validateId(service.id)

    require(service.type.length < maxServiceTypeLength) {
      "service type \"${service.type}\" exceeds max allowed length of $maxServiceTypeLength"
    }

    try {
      URI.create(service.serviceEndpoint)
    } catch (e: Exception) {
      throw IllegalArgumentException("service endpoint is not a valid URI", e)
    }
  }

  private fun validateId(id: String) {
    require(isBase64UrlString(id)) { "id \"$id\" is not base 64 url charset" }

    require(id.length <= maxIdLength) {
      "id \"$id\" exceeds max allowed length of $maxIdLength"
    }
  }

  private fun isBase64UrlString(input: String): Boolean {
    return base64UrlCharsetRegex.matches(input)
  }

  private fun createOperationSuffixDataObject(
    createOperationDeltaObject: Delta,
    recoveryCommitment: Commitment): OperationSuffixDataObject {
    val jsonString = mapper.writeValueAsString(createOperationDeltaObject)
    val canonicalized = JsonCanonicalizer(jsonString).encodedUTF8
    val deltaMultihash = multihash(canonicalized)

    return OperationSuffixDataObject(
      deltaHash = Convert(deltaMultihash).toBase64Url(padding = false),
      recoveryCommitment = recoveryCommitment
    )
  }

  internal fun createRecoverOperation(keyManager: KeyManager, did: String, options: RecoverDidIonOptions):
    Pair<SidetreeRecoverOperation, KeyAliases> {
    val parsedDid = DID.fromString(did)
    require(!parsedDid.methodSpecificId.contains(":")) {
      "recovering a DID is only allowed for short form dids, but got $did"
    }

    val recoveryPublicKey = keyManager.getPublicKey(options.recoveryKeyAlias)
    val reveal = recoveryPublicKey.reveal()

    val nextRecoveryKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val nextRecoveryPublicKey = keyManager.getPublicKey(nextRecoveryKeyAlias)
    val nextRecoveryCommitment = nextRecoveryPublicKey.commitment()

    val nextUpdateKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val nextUpdatePublicKey = keyManager.getPublicKey(nextUpdateKeyAlias)
    val nextUpdateCommitment = nextUpdatePublicKey.commitment()

    val publicKeyWithAliases = publicKeysWithAliasesToAdd(options, keyManager)
    val publicKeysToAdd = publicKeyWithAliases.map { it.second }
    validateDidDocumentKeys(publicKeysToAdd)

    validateServices(options.servicesToAdd)

    val delta = Delta(
      patches = options.toPatches(publicKeysToAdd),
      updateCommitment = nextUpdateCommitment
    )
    val deltaHash = deltaHash(delta)

    val dataToBeSigned = RecoveryUpdateSignedData(
      recoveryCommitment = nextRecoveryCommitment,
      recoveryKey = recoveryPublicKey,
      deltaHash = deltaHash
    )

    val jwsObject = sign(dataToBeSigned, keyManager, options.recoveryKeyAlias)

    return Pair(
      SidetreeRecoverOperation(
        type = "recover",
        didSuffix = parsedDid.methodSpecificId,
        revealValue = reveal,
        delta = delta,
        signedData = jwsObject.serialize(),
      ),
      KeyAliases(
        updateKeyAlias = nextUpdateKeyAlias,
        verificationKeyAliases = publicKeyWithAliases.mapNotNull { it.first },
        recoveryKeyAlias = nextRecoveryKeyAlias,
      )
    )
  }

  private fun createDeactivateOperation(
    keyManager: KeyManager,
    did: String,
    options: DeactivateDidIonOptions): SidetreeDeactivateOperation {
    val parsedDid = DID.fromString(did)
    require(!parsedDid.methodSpecificId.contains(":")) {
      "deactivating a DID is only allowed for short form dids, but got $did"
    }
    val recoveryPublicKey = keyManager.getPublicKey(options.recoveryKeyAlias)
    val reveal = recoveryPublicKey.reveal()


    val dataToBeSigned = DeactivateUpdateSignedData(
      didSuffix = parsedDid.methodSpecificId,
      recoveryKey = recoveryPublicKey,
    )

    val jwsObject = sign(dataToBeSigned, keyManager, options.recoveryKeyAlias)

    return SidetreeDeactivateOperation(
      type = "deactivate",
      didSuffix = parsedDid.methodSpecificId,
      revealValue = reveal,
      signedData = jwsObject.serialize(),
    )
  }

  /**
   * Recovers [did] with the given [options]. The `recoveryKeyAlias` value must be available in the [keyManager].
   * Depending on the options provided, will create new keys using [keyManager]. See [RecoverDidIonOptions] for more
   * details.
   */
  public fun recover(keyManager: KeyManager, did: String, options: RecoverDidIonOptions): IonRecoverResult {
    val (recoverOp, keyAliases) = createRecoverOperation(keyManager, did, options)

    val response: HttpResponse = runBlocking {
      client.post(operationsEndpoint) {
        contentType(ContentType.Application.Json)
        setBody(recoverOp)
      }
    }

    val opBody = runBlocking {
      response.bodyAsText()
    }
    return IonRecoverResult(
      keyAliases = keyAliases,
      recoverOperation = recoverOp,
      operationsResponse = opBody,
    )
  }

  /**
   * Deactivates [did] with the given [options]. The `recoveryKeyAlias` value must be available in the [keyManager].
   */
  public fun deactivate(keyManager: KeyManager, did: String, options: DeactivateDidIonOptions): IonDeactivateResult {
    val deactivateOp = createDeactivateOperation(keyManager, did, options)

    val response: HttpResponse = runBlocking {
      client.post(operationsEndpoint) {
        contentType(ContentType.Application.Json)
        setBody(deactivateOp)
      }
    }

    val opBody = runBlocking {
      response.bodyAsText()
    }

    return IonDeactivateResult(
      deactivateOperation = deactivateOp,
      operationsResponse = opBody,
    )
  }
}

private fun CommonOptions?.toPatches(publicKeysToAdd: Iterable<PublicKey>): Iterable<PatchAction> {
  return listOf(
    ReplaceAction(
      Document(
        publicKeys = publicKeysToAdd,
        services = this?.servicesToAdd ?: emptyList()
      )
    )
  )
}

/**
 * Data associated with the [DidIonApi.deactivate] call. Useful for debugging and testing purposes.
 */
public class IonDeactivateResult(
  public val deactivateOperation: SidetreeDeactivateOperation,
  public val operationsResponse: String)

/**
 * All the data associated with the [recover] call. Useful for advanced, and debugging, purposes.
 */
public class IonRecoverResult(
  public val keyAliases: KeyAliases,
  public val recoverOperation: SidetreeRecoverOperation,
  public val operationsResponse: String)

private interface CommonOptions {
  val verificationMethodsToAdd: Iterable<VerificationMethodSpec>
  val servicesToAdd: Iterable<Service>
}

private fun JWK.commitment(): Commitment {
  require(!this.isPrivate) { throw IllegalArgumentException("provided JWK must not be a private key") }

  val pkJson = this.toJSONString()
  val canonicalized = JsonCanonicalizer(pkJson).encodedUTF8

  val sha256 = MessageDigest.getInstance("SHA-256")
  val pkDigest = sha256.digest(canonicalized)

  val pkDigestMultihash = multihash(pkDigest)
  return Commitment(pkDigestMultihash)
}

private fun JWK.reveal(): Reveal {
  require(!this.isPrivate) { throw IllegalArgumentException("provided JWK must not be a private key") }

  val pkJson = this.toJSONString()
  val canonicalized = JsonCanonicalizer(pkJson).encodedUTF8

  val mh = multihash(canonicalized)
  return Reveal(mh)
}

/**
 * Computes a multihash of the given payload.
 *
 * A multihash is a protocol for differentiating outputs from various well-established cryptographic hash functions,
 * addressing size and encoding considerations.
 *
 * This function specifically calculates the SHA-256 hash of the input payload, then prefixes the result with
 * the multicodec identifier for SHA-256 and the digest length. The multicodec identifier is a predetermined
 * byte array
 *
 * @param payload The input data for which the multihash needs to be calculated.
 * @return A byte array representing the multihash of the input payload. It includes the multicodec prefix,
 *         the length of the hash digest, and the hash digest itself.
 */
public fun multihash(payload: ByteArray): ByteArray {
  val sha256 = MessageDigest.getInstance("SHA-256")
  sha256.update(payload)

  val digestLen = sha256.digestLength
  val digest = sha256.digest()

  return sha256MultiCodec + Varint.encode(digestLen) + digest
}

/**
 * Metadata related to the update of an ion DID.
 */
public data class IonUpdateResult(
  public val operationsResponseBody: String,
  public val keyAliases: KeyAliases
)

/**
 * Represents an HTTP response where the status code is outside the range considered success.
 */
public class InvalidStatusException(public val statusCode: Int, msg: String) : RuntimeException(msg)

/**
 * Represents an exception where the response from calling [DidIonApi.resolve] contains a non-empty value in
 * [DidResolutionMetadata.error].
 *
 * Note: This exception is only thrown when calling [DidIonApi.create]. Callers of [DidIonApi.resolve] should
 * handle possible values of [DidResolutionMetadata.error] within [DidResolutionResult].
 */
public class ResolutionException(msg: String) : RuntimeException(msg)

/**
 * Container for the key aliases for an ION did.
 */
public data class KeyAliases(
  public val updateKeyAlias: String?,
  public val verificationKeyAliases: List<String>,
  public val recoveryKeyAlias: String?)

/**
 * Options available when creating an ion did.
 *
 *
 * @param verificationMethodsToAdd List of specs that will be added to the DID ION document.
 * @param servicesToAdd When provided, the services will be added to the DID document. Note that for each of the
 * services that should be added, the following must hold:
 *   - The `id` field cannot be over 50 chars and must only use characters from the Base64URL character set.
 *   - The `type` field cannot be over 30 characters.
 *   - The `serviceEndpoint` must be a valid URI.
 */
public class CreateDidIonOptions(
  override val verificationMethodsToAdd: Iterable<VerificationMethodSpec> = emptyList(),
  override val servicesToAdd: Iterable<Service> = emptyList(),
) : CreateDidOptions, CommonOptions

/** Common interface for options available when adding a VerificationMethod. */
public interface VerificationMethodSpec

private interface VerificationMethodGenerator {
  fun generate(): Pair<String?, PublicKey>
}

/**
 * A [VerificationMethodSpec] where a [KeyManager] will be used to generate the underlying verification method keys.
 * The parameters [algorithm], [curve], and [options] will be forwarded to the keyManager.
 *
 * [relationships] will be used to determine the verification relationships in the DID Document being created.
 * */
public class VerificationMethodCreationParams(
  public val algorithm: Algorithm,
  public val curve: Curve? = null,
  public val options: KeyGenOptions? = null,
  public val relationships: Iterable<PublicKeyPurpose>
) : VerificationMethodSpec {
  internal fun toGenerator(keyManager: KeyManager): VerificationMethodKeyManagerGenerator {
    return VerificationMethodKeyManagerGenerator(keyManager, this)
  }
}

/**
 * A [VerificationMethodSpec] according to https://w3c-ccg.github.io/lds-jws2020/.
 *
 * The [id] property cannot be over 50 chars and must only use characters from the Base64URL character set.
 */
public class JsonWebKey2020VerificationMethod(
  public val id: String,
  public val controller: String? = null,
  public val publicKeyJwk: JWK,
  public val relationships: Iterable<PublicKeyPurpose> = emptySet()
) : VerificationMethodSpec, VerificationMethodGenerator {
  override fun generate(): Pair<String?, PublicKey> {
    return Pair(null, PublicKey(id, "JsonWebKey2020", controller, publicKeyJwk, relationships))
  }
}

/**
 * A [VerificationMethodSpec] according to https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/.
 *
 * The [id] property cannot be over 50 chars and must only use characters from the Base64URL character set.
 */
public class EcdsaSecp256k1VerificationKey2019VerificationMethod(
  public val id: String,
  public val controller: String? = null,
  public val publicKeyJwk: JWK,
  public val relationships: Iterable<PublicKeyPurpose> = emptySet()
) : VerificationMethodSpec, VerificationMethodGenerator {
  override fun generate(): Pair<String, PublicKey> {
    return Pair(id, PublicKey(id, "EcdsaSecp256k1VerificationKey2019", controller, publicKeyJwk, relationships))
  }
}

internal class VerificationMethodKeyManagerGenerator(
  val keyManager: KeyManager,
  val params: VerificationMethodCreationParams,
) : VerificationMethodGenerator {

  override fun generate(): Pair<String, PublicKey> {
    val alias = keyManager.generatePrivateKey(
      algorithm = params.algorithm,
      curve = params.curve,
      options = params.options
    )
    val publicKeyJwk = keyManager.getPublicKey(alias)
    return Pair(
      alias,
      PublicKey(
        id = UUID.randomUUID().toString(),
        type = "JsonWebKey2020",
        publicKeyJwk = publicKeyJwk,
        purposes = params.relationships,
      )
    )
  }
}


private fun Iterable<VerificationMethodSpec>.toGenerators(keyManager: KeyManager): List<VerificationMethodGenerator> {
  return buildList {
    for (verificationMethodSpec in this@toGenerators) {
      when (verificationMethodSpec) {
        is VerificationMethodCreationParams -> add(verificationMethodSpec.toGenerator(keyManager))

        is VerificationMethodGenerator -> add(verificationMethodSpec)
      }
    }
  }

}

private fun Iterable<VerificationMethodSpec>.toPublicKeys(keyManager: KeyManager) = toGenerators(
  keyManager
).map { it.generate() }

/**
 * Metadata related to the creation of a DID (Decentralized Identifier) on the Sidetree protocol.
 *
 * @property createOperation The Sidetree create operation used to create the DID.
 * @property shortFormDid The short-form DID representing the DID created.
 * @property longFormDid The long-form DID representing the DID created.
 * @property operationsResponseBody The response body received after submitting the create operation.
 */
public data class IonCreationMetadata(
  public val createOperation: SidetreeCreateOperation,
  public val shortFormDid: String,
  public val longFormDid: String,
  public val operationsResponseBody: String,
  public val keyAliases: KeyAliases,
) : CreationMetadata