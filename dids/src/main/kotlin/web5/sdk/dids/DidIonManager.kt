package web5.sdk.dids

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
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
import org.erwinkok.multiformat.multicodec.Multicodec
import org.erwinkok.multiformat.multihash.Multihash
import org.erwinkok.result.get
import org.erwinkok.result.getOrThrow
import web5.sdk.common.Convert
import web5.sdk.common.InvalidStatusException
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.ion.model.AddPublicKeysAction
import web5.sdk.dids.ion.model.AddServicesAction
import web5.sdk.dids.ion.model.Commitment
import web5.sdk.dids.ion.model.DeactivateUpdateSignedData
import web5.sdk.dids.ion.model.Delta
import web5.sdk.dids.ion.model.Document
import web5.sdk.dids.ion.model.InitialState
import web5.sdk.dids.ion.model.OperationSuffixDataObject
import web5.sdk.dids.ion.model.PatchAction
import web5.sdk.dids.ion.model.PublicKey
import web5.sdk.dids.ion.model.RecoveryUpdateSignedData
import web5.sdk.dids.ion.model.RemovePublicKeysAction
import web5.sdk.dids.ion.model.RemoveServicesAction
import web5.sdk.dids.ion.model.ReplaceAction
import web5.sdk.dids.ion.model.Reveal
import web5.sdk.dids.ion.model.Service
import web5.sdk.dids.ion.model.SidetreeCreateOperation
import web5.sdk.dids.ion.model.SidetreeDeactivateOperation
import web5.sdk.dids.ion.model.SidetreeRecoverOperation
import web5.sdk.dids.ion.model.SidetreeUpdateOperation
import web5.sdk.dids.ion.model.UpdateOperationSignedData
import java.net.URI
import java.util.UUID

private const val operationsPath = "/operations"
private const val identifiersPath = "/identifiers"

/**
 * Configuration for the [DidIonManager].
 *
 * @property ionHost The ION host URL.
 * @property engine The engine to use. When absent, a new one will be created from the [CIO] factory.
 */
public class DidIonConfiguration internal constructor(
  public var ionHost: String = "https://ion.tbddev.org",
  public var engine: HttpClientEngine? = null,
)


/**
 * Returns a [DidIonManager] after applying the provided configuration [builderAction].
 */
public fun DidIonManager(builderAction: DidIonConfiguration.() -> Unit): DidIonManager {
  val conf = DidIonConfiguration().apply(builderAction)
  return DidIonManagerImpl(conf)
}

/** [DidIonManager]is sealed, so we provide an impl so the constructor can be called. */
private class DidIonManagerImpl(configuration: DidIonConfiguration) : DidIonManager(configuration)

/**
 * The options when updating an ION did.
 *
 * @param didString The full did. e.g. `did:ion:123`
 * @param updateKeyAlias The alias within the key manager that refers to the last update key.
 * @param servicesToAdd The services to add in the did document.
 * @param idsOfServicesToRemove Ids of the services to remove from the did document.
 * @param publicKeysToAdd PublicKeys to add to the DID document.
 * @param idsOfPublicKeysToRemove Keys to remove from the DID document.
 */
public data class UpdateDidIonOptions(
  val didString: String,
  val updateKeyAlias: String,
  val servicesToAdd: Iterable<Service> = emptyList(),
  val idsOfServicesToRemove: Iterable<String> = emptyList(),
  val publicKeysToAdd: Iterable<PublicKey> = emptyList(),
  val idsOfPublicKeysToRemove: Iterable<String> = emptyList()
) {
  internal fun toPatches(): List<PatchAction> {
    fun <T> MutableList<PatchAction>.addIfNotEmpty(iter: Iterable<T>, action: (Iterable<T>) -> PatchAction) {
      iter.takeIf { it.count() != 0 }?.let { this.add(action(it)) }
    }

    return buildList {
      addIfNotEmpty(servicesToAdd, ::AddServicesAction)
      addIfNotEmpty(idsOfServicesToRemove, ::RemoveServicesAction)
      addIfNotEmpty(publicKeysToAdd, ::AddPublicKeysAction)
      addIfNotEmpty(idsOfPublicKeysToRemove, ::RemovePublicKeysAction)
    }
  }
}

/**
 * The options when recovering an ION did.
 *
 * - [did] is the did to recover. I.e. "did:ion:1234".
 * - [recoveryKeyAlias] is the alias under which the recovery private key is stored inside the [KeyManager] used.
 * - [verificationPublicKey] When provided, will be used as the verification key in the DID document.
 * - [updatePublicJwk] When provided, will be used to create the update key commitment. Otherwise, it will be generated
 *   and stored within the [KeyManager] used.
 * - [recoveryPublicJwk] When provided, will be used to create the recovery key commitment. Otherwise, it will be
 *   generated and stored within the [KeyManager] used.
 * - [verificationMethodId] When provided, will be used as the verification method id. Cannot be over 50 chars and
 *   must only use characters from the Base64URL character set. When absent, a [UUID] will be generated.
 * - [servicesToAdd] List of services which will be added into the DID document that results after the update
 *   operation.
 */
public class RecoverDidIonOptions(
  public val did: String,
  public val recoveryKeyAlias: String,
  public override val verificationPublicKey: PublicKey? = null,
  public val updatePublicJwk: JWK? = null,
  public val recoveryPublicJwk: JWK? = null,
  public override val verificationMethodId: String? = null,
  public val servicesToAdd: Iterable<Service> = emptySet(),
) : VerificationPublicKeyOption {
  internal fun toPatches(verificationPublicKey: PublicKey): List<PatchAction> = listOf(
    ReplaceAction(
      Document(
        publicKeys = listOf(
          verificationPublicKey
        ),
        services = servicesToAdd
      )
    )
  )
}

/**
 * Options when deactivating an ION did.
 *
 * [recoveryKeyAlias] is the alias within the keyManager to use when signing. It must match the recovery used with the
 * last recovery operation.
 * [did] is the DID that will be deactivated. E.g. "did:ion:123123".
 */
public class DeactivateDidIonOptions(public val recoveryKeyAlias: String, public val did: String)


/**
 * Provides a specific implementation for creating and resolving "did:ion" method Decentralized Identifiers (DIDs).
 *
 * A "did:ion" DID is an implementation of the Sidetree protocol that uses Bitcoin as it's anchoring system.
 * Further specifics and technical details are outlined in [the DID Sidetree Spec](https://identity.foundation/sidetree/spec/).
 *
 * @property uri The URI of the "did:ion" which conforms to the DID standard.
 * @property keyManager A [KeyManager] instance utilized to manage the cryptographic keys associated with the DID.
 * @property creationMetadata Metadata related to the creation of a DID. Useful for debugging purposes.
 *
 * ### Usage Example:
 * ```kotlin
 * val keyManager = InMemoryKeyManager()
 * val did = DidIonHandle("did:ion:example", keyManager)
 * ```
 */
public class DidIonHandle(
  uri: String,
  keyManager: KeyManager,
  public val creationMetadata: IonCreationMetadata? = null) : Did(uri, keyManager)

private const val maxServiceTypeLength = 30

private const val maxIdLength = 50

private const val base64UrlCharsetRegexStr = "^[A-Za-z0-9_-]+$"

private val base64UrlCharsetRegex = base64UrlCharsetRegexStr.toRegex()

/**
 * Base class for managing DID Ion operations. Uses the given [configuration].
 */
public sealed class DidIonManager(
  private val configuration: DidIonConfiguration
) : DidMethod<DidIonHandle, CreateDidIonOptions> {

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
   * Creates a [DidIonHandle], which includes a DID and it's associated DID Document. In order to ensure the creation
   * works appropriately, the DID is resolved immediately after it's created.
   *
   * Note: [options] must be of type [CreateDidIonOptions].
   * @throws [ResolutionException] When there is an error after resolution.
   * @throws [InvalidStatusException] When any of the network requests return an invalid HTTP status code.
   * @see [DidMethod.create] for details of each parameter.
   */
  override fun create(keyManager: KeyManager, options: CreateDidIonOptions?): DidIonHandle {
    val (createOp, keys) = createOperation(keyManager, options)

    val shortFormDidSegment = Convert(
      Multihash.sum(Multicodec.SHA2_256, canonicalized(createOp.suffixData)).get()?.bytes()
    ).toBase64Url(padding = false)
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

      return DidIonHandle(
        resolutionResult.didDocument.id.toString(),
        keyManager,
        IonCreationMetadata(
          createOp,
          shortFormDid,
          longFormDid,
          opBody,
          keys
        )
      )
    }
    throw InvalidStatusException(response.status.value, "received error response: '$opBody'")
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
   * Updates an ION did with the given [options]. The update key must be available in the [keyManager].
   */
  public fun update(keyManager: KeyManager, options: UpdateDidIonOptions): IonUpdateResult {
    val (updateOp, newUpdateKeyAlias) = createUpdateOperation(keyManager, options)
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
        updateKeyAlias = newUpdateKeyAlias,
      )
    }
    throw InvalidStatusException(response.status.value, "received error response: '$opBody'")
  }

  private fun createUpdateOperation(keyManager: KeyManager, options: UpdateDidIonOptions):
    Pair<SidetreeUpdateOperation, String> {
    val updatePublicKey = keyManager.getPublicKey(options.updateKeyAlias)

    val newUpdateKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val newUpdatePublicKey = keyManager.getPublicKey(newUpdateKeyAlias)

    val reveal = updatePublicKey.reveal()
    val commitment = newUpdatePublicKey.commitment()

    validateServices(options.servicesToAdd)

    validateDidDocumentKeys(options.publicKeysToAdd)

    val updateOpDeltaObject = Delta(
      patches = options.toPatches(),
      updateCommitment = commitment
    )

    val deltaHash = deltaHash(updateOpDeltaObject)

    val updateOpSignedData = UpdateOperationSignedData(
      updateKey = updatePublicKey,
      deltaHash = deltaHash,
    )
    val signedJwsObject = sign(updateOpSignedData, keyManager, options.updateKeyAlias)

    val did = DID.fromString(options.didString)
    return Pair(
      SidetreeUpdateOperation(
        type = "update",
        didSuffix = did.methodSpecificId,
        revealValue = reveal,
        delta = updateOpDeltaObject,
        signedData = signedJwsObject.serialize(false),
      ),
      newUpdateKeyAlias,
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
    val canonicalized = canonicalized(updateOpDeltaObject)
    val deltaHashBytes = Multihash.sum(Multicodec.SHA2_256, canonicalized).getOrThrow().bytes()
    return Base64URL.encode(deltaHashBytes).toString()
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

  private fun createOperation(keyManager: KeyManager, options: CreateDidIonOptions?)
    : Pair<SidetreeCreateOperation, KeyAliases> {
    val (updatePublicJwk, updateKeyAlias) = if (options?.updatePublicJwk == null) {
      val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
      Pair(keyManager.getPublicKey(alias), alias)
    } else {
      Pair(options.updatePublicJwk, null)
    }

    val publicKeyCommitment = updatePublicJwk.commitment()

    val (verificationPublicKey, verificationKeyAlias) = getVerificationPublicKeyOrDefault(options, keyManager)

    val services = options?.servicesToAdd?.toList() ?: emptyList()
    validateServices(services)

    val patches = listOf(
      ReplaceAction(
        Document(
          publicKeys = listOf(verificationPublicKey),
          services = services,
        )
      )
    )
    val createOperationDelta = Delta(
      patches = patches,
      updateCommitment = publicKeyCommitment
    )

    val (recoveryPublicJwk, recoveryKeyAlias) = if (options?.recoveryPublicJwk == null) {
      val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
      Pair(keyManager.getPublicKey(alias), alias)
    } else {
      Pair(options.recoveryPublicJwk, null)
    }
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
        verificationKeyAlias = verificationKeyAlias,
        recoveryKeyAlias = recoveryKeyAlias
      )
    )
  }

  private fun getVerificationMethodIdOrDefault(options: VerificationPublicKeyOption?) =
    when (options?.verificationMethodId) {
      null -> UUID.randomUUID().toString()
      else -> {
        validateId(options.verificationMethodId!!)
        options.verificationMethodId!!
      }
    }

  private fun getVerificationPublicKeyOrDefault(options: VerificationPublicKeyOption?, keyManager: KeyManager) =
    if (options?.verificationPublicKey == null) {
      val verificationMethodId = getVerificationMethodIdOrDefault(options)
      val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
      val verificationJwk = keyManager.getPublicKey(alias)
      Pair(
        PublicKey(
          id = verificationMethodId,
          type = "JsonWebKey2020",
          publicKeyJwk = verificationJwk,
          purposes = listOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.ASSERTION_METHOD),
        ),
        alias
      )
    } else {
      Pair(options.verificationPublicKey!!, null)
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
    val deltaHashBytes = Multihash.sum(Multicodec.SHA2_256, canonicalized).getOrThrow().bytes()
    val deltaHash = Convert(deltaHashBytes).toBase64Url(padding = false)
    return OperationSuffixDataObject(
      deltaHash = deltaHash,
      recoveryCommitment = recoveryCommitment
    )
  }

  internal fun createRecoverOperation(keyManager: KeyManager, options: RecoverDidIonOptions):
    Pair<SidetreeRecoverOperation, KeyAliases> {
    val recoveryPublicKey = keyManager.getPublicKey(options.recoveryKeyAlias)
    val reveal = recoveryPublicKey.reveal()

    val nextRecoveryKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val nextRecoveryPublicKey = keyManager.getPublicKey(nextRecoveryKeyAlias)
    val nextRecoveryCommitment = nextRecoveryPublicKey.commitment()

    val nextUpdateKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val nextUpdatePublicKey = keyManager.getPublicKey(nextUpdateKeyAlias)
    val nextUpdateCommitment = nextUpdatePublicKey.commitment()

    val (verificationPublicKey, verificationKeyAlias) = getVerificationPublicKeyOrDefault(options, keyManager)

    val delta = Delta(
      patches = options.toPatches(verificationPublicKey),
      updateCommitment = nextUpdateCommitment
    )
    val deltaHash = deltaHash(delta)

    val dataToBeSigned = RecoveryUpdateSignedData(
      recoveryCommitment = nextRecoveryCommitment,
      recoveryKey = recoveryPublicKey,
      deltaHash = deltaHash
    )

    val jwsObject = sign(dataToBeSigned, keyManager, options.recoveryKeyAlias)

    val did = DID.fromString(options.did)
    return Pair(
      SidetreeRecoverOperation(
        type = "recover",
        didSuffix = did.methodSpecificId,
        revealValue = reveal,
        delta = delta,
        signedData = jwsObject.serialize(),
      ),
      KeyAliases(
        updateKeyAlias = nextUpdateKeyAlias,
        verificationKeyAlias = verificationKeyAlias,
        recoveryKeyAlias = nextRecoveryKeyAlias,
      )
    )
  }

  private fun createDeactivateOperation(
    keyManager: KeyManager,
    options: DeactivateDidIonOptions): SidetreeDeactivateOperation {
    val recoveryPublicKey = keyManager.getPublicKey(options.recoveryKeyAlias)
    val reveal = recoveryPublicKey.reveal()

    val did = DID.fromString(options.did)

    val dataToBeSigned = DeactivateUpdateSignedData(
      didSuffix = did.methodSpecificId,
      recoveryKey = recoveryPublicKey,
    )

    val jwsObject = sign(dataToBeSigned, keyManager, options.recoveryKeyAlias)

    return SidetreeDeactivateOperation(
      type = "deactivate",
      didSuffix = did.methodSpecificId,
      revealValue = reveal,
      signedData = jwsObject.serialize(),
    )
  }

  /**
   * Recovers an ION did with the given [options]. The `recoveryKeyAlias` value must be available in the [keyManager].
   * Depending on the options provided, will create new keys using [keyManager]. See [RecoverDidIonOptions] for more
   * details.
   */
  public fun recover(keyManager: KeyManager, options: RecoverDidIonOptions): IonRecoverResult {
    val (recoverOp, keyAliases) = createRecoverOperation(keyManager, options)

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
   * Deactivates an ION did with the given [options]. The `recoveryKeyAlias` value must be available in the [keyManager].
   */
  public fun deactivate(keyManager: KeyManager, options: DeactivateDidIonOptions): IonDeactivateResult {
    val deactivateOp = createDeactivateOperation(keyManager, options)

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


  /**
   * Default companion object for creating a [DidIonManager] with a default configuration.
   */
  public companion object Default : DidIonManager(DidIonConfiguration())
}

/**
 * Data associated with the [DidIonManager.deactivate] call. Useful for debugging and testing purposes.
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

private interface VerificationPublicKeyOption {
  val verificationPublicKey: PublicKey?
  val verificationMethodId: String?
}

private fun JWK.commitment(): Commitment {
  require(!this.isPrivate) { throw IllegalArgumentException("provided JWK must not be a private key") }
  // 1. Encode the public key into the form of a valid JWK.
  val pkJson = this.toJSONString()

  // 2. Canonicalize the JWK encoded public key using the implementation’s JSON_CANONICALIZATION_SCHEME.
  val canonicalized = JsonCanonicalizer(pkJson).encodedUTF8

  // 3. Use the implementation’s HASH_PROTOCOL to Multihash the canonicalized public key to generate the REVEAL_VALUE,
  val mh = Multihash.sum(Multicodec.SHA2_256, canonicalized).getOrThrow()
  val intermediate = mh.digest

  // then Multihash the resulting Multihash value again using the implementation’s HASH_PROTOCOL to produce
  // the public key commitment.
  val hashOfHash = Multihash.sum(Multicodec.SHA2_256, intermediate).getOrThrow().bytes()
  return Commitment(hashOfHash)
}

private fun JWK.reveal(): Reveal {
  require(!this.isPrivate) { throw IllegalArgumentException("provided JWK must not be a private key") }
  // 1. Encode the public key into the form of a valid JWK.
  val pkJson = this.toJSONString()

  // 2. Canonicalize the JWK encoded public key using the implementation’s JSON_CANONICALIZATION_SCHEME.
  val canonicalized = JsonCanonicalizer(pkJson).encodedUTF8

  // 3. Use the implementation’s HASH_PROTOCOL to Multihash the canonicalized public key to generate the REVEAL_VALUE,
  val mh = Multihash.sum(Multicodec.SHA2_256, canonicalized).getOrThrow()
  return Reveal(mh.bytes())
}

/**
 * Metadata related to the update of an ion DID.
 */
public data class IonUpdateResult(
  public val operationsResponseBody: String,
  public val updateKeyAlias: String
)

/**
 * Represents an exception where the response from calling [DidIonManager.resolve] contains a non-empty value in
 * [DidResolutionMetadata.error].
 *
 * Note: This exception is only thrown when calling [DidIonManager.create]. Callers of [DidIonManager.resolve] should
 * handle possible values of [DidResolutionMetadata.error] within [DidResolutionResult].
 */
public class ResolutionException(msg: String) : RuntimeException(msg)

/**
 * Container for the key aliases for an ION did.
 */
public data class KeyAliases(
  public val updateKeyAlias: String?,
  public val verificationKeyAlias: String?,
  public val recoveryKeyAlias: String?)

/**
 * Options available when creating an ion did.
 *
 * @param verificationPublicKey When provided, will be used as the verification key in the DID document.
 * @param updatePublicJwk When provided, will be used to create the update key commitment.
 * @param recoveryPublicJwk When provided, will be used to create the recovery key commitment.
 * @param verificationMethodId When provided, will be used as the verification method id. Cannot be over 50 chars and
 * must only use characters from the Base64URL character set.
 * @param servicesToAdd When provided, the services will be added to the DID document. Note that for each of the
 * services that should be added, the following must hold:
 *   - The `id` field cannot be over 50 chars and must only use characters from the Base64URL character set.
 *   - The `type` field cannot be over 30 characters.
 *   - The `serviceEndpoint` must be a valid URI.
 */
public class CreateDidIonOptions(
  public override val verificationPublicKey: PublicKey? = null,
  public val updatePublicJwk: JWK? = null,
  public val recoveryPublicJwk: JWK? = null,
  public override val verificationMethodId: String? = null,
  public val servicesToAdd: Iterable<Service>? = null,
) : CreateDidOptions, VerificationPublicKeyOption

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