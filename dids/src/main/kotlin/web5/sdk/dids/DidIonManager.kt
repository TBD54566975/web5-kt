package web5.sdk.dids

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSAlgorithm
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
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.ion.model.Commitment
import web5.sdk.dids.ion.model.Delta
import web5.sdk.dids.ion.model.Document
import web5.sdk.dids.ion.model.InitialState
import web5.sdk.dids.ion.model.OperationSuffixDataObject
import web5.sdk.dids.ion.model.PublicKey
import web5.sdk.dids.ion.model.PublicKeyPurpose
import web5.sdk.dids.ion.model.ReplaceAction
import web5.sdk.dids.ion.model.SidetreeCreateOperation
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

/** [DidIonManager] is sealed, so we provide an impl so the constructor can be called. */
private class DidIonManagerImpl(configuration: DidIonConfiguration) : DidIonManager(configuration)

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
 * val did = DidKey("did:key:example", keyManager)
 * ```
 */
public class DidIonHandle(
  uri: String,
  keyManager: KeyManager,
  public val creationMetadata: IonCreationMetadata? = null) : Did(uri, keyManager)

private const val maxVerificationMethodIdLength = 50

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
    throw InvalidStatusException("received error response '$opBody'")
  }

  private fun canonicalized(data: Any): ByteArray {
    val jsonString = mapper.writeValueAsString(data)
    return JsonCanonicalizer(jsonString).encodedUTF8
  }

  private fun didUriSegment(initialState: InitialState): String {
    val canonicalized = canonicalized(initialState)
    return Base64URL.encode(canonicalized).toString()
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
      throw InvalidStatusException("resolution error response '$body'")
    }
    return mapper.readValue(body, DidResolutionResult::class.java)
  }

  private fun createOperation(keyManager: KeyManager, options: CreateDidIonOptions?)
    : Pair<SidetreeCreateOperation, KeyAliases> {
    val updatePublicJWK: JWK = options?.updatePublicJWK ?: keyManager.getPublicKey(
      keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    )

    val publicKeyCommitment: String = publicKeyCommitment(updatePublicJWK)

    val verificationMethodId = when (options?.verificationMethodId) {
      null -> UUID.randomUUID().toString()
      else -> {
        validateVerificationMethodId(options.verificationMethodId)
        options.verificationMethodId
      }
    }
    val verificationPublicKey = if (options?.verificationPublicKey == null) {
      val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
      val verificationJWK = keyManager.getPublicKey(alias)
      PublicKey(
        id = verificationMethodId,
        type = "JsonWebKey2020",
        publicKeyJwk = verificationJWK,
        purposes = listOf(PublicKeyPurpose.AUTHENTICATION),
      )
    } else {
      options.verificationPublicKey
    }
    val patches = listOf(ReplaceAction(Document(listOf(verificationPublicKey))))
    val createOperationDelta = Delta(
      patches = patches,
      updateCommitment = publicKeyCommitment
    )

    val recoveryPublicJWK = if (options?.recoveryPublicJWK == null) {
      val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
      keyManager.getPublicKey(alias)
    } else {
      options.recoveryPublicJWK
    }
    val recoveryCommitment = publicKeyCommitment(recoveryPublicJWK)

    val operation: OperationSuffixDataObject =
      createOperationSuffixDataObject(createOperationDelta, recoveryCommitment)

    return Pair(
      SidetreeCreateOperation(
        type = "create",
        suffixData = operation,
        delta = createOperationDelta,
      ),
      KeyAliases(
        updateKeyAlias = updatePublicJWK.keyID,
        verificationKeyAlias = verificationPublicKey.publicKeyJwk!!.keyID,
        recoveryKeyAlias = recoveryPublicJWK.keyID
      )
    )
  }

  private fun validateVerificationMethodId(id: String) {
    if (!isBase64UrlString(id)) {
      throw IllegalArgumentException("verification method id \"$id\" is not base 64 url charset")
    }

    if (id.length > maxVerificationMethodIdLength) {
      throw IllegalArgumentException(
        "verification method id \"$id\" exceeds max allowed length of $maxVerificationMethodIdLength"
      )
    }
  }

  private fun isBase64UrlString(input: String?): Boolean {
    return base64UrlCharsetRegex.matches(input!!)
  }

  private fun createOperationSuffixDataObject(
    createOperationDeltaObject: Delta,
    recoveryCommitment: String): OperationSuffixDataObject {
    val jsonString = mapper.writeValueAsString(createOperationDeltaObject)
    val canonicalized = JsonCanonicalizer(jsonString).encodedUTF8
    val deltaHash = Multihash.sum(Multicodec.SHA2_256, canonicalized).get()?.bytes()
    return OperationSuffixDataObject(
      deltaHash = Base64URL.encode(deltaHash).toString(),
      recoveryCommitment = recoveryCommitment
    )
  }

  private fun publicKeyCommitment(publicKeyJWK: JWK): Commitment {
    require(!publicKeyJWK.isPrivate) { throw IllegalArgumentException("provided JWK must not be a private key") }
    // 1. Encode the public key into the form of a valid JWK.
    val pkJson = publicKeyJWK.toJSONString()

    // 2. Canonicalize the JWK encoded public key using the implementation’s JSON_CANONICALIZATION_SCHEME.
    val canonicalized = JsonCanonicalizer(pkJson).encodedUTF8

    // 3. Use the implementation’s HASH_PROTOCOL to Multihash the canonicalized public key to generate the REVEAL_VALUE,
    val intermediate = Multihash.sum(Multicodec.SHA2_256, canonicalized).getOrThrow().digest

    // then Multihash the resulting Multihash value again using the implementation’s HASH_PROTOCOL to produce
    // the public key commitment.
    val hashOfHash = Multihash.sum(Multicodec.SHA2_256, intermediate).getOrThrow().bytes()
    return Base64URL.encode(hashOfHash).toString()
  }

  /**
   * Default companion object for creating a [DidIonManager] with a default configuration.
   */
  public companion object Default : DidIonManager(DidIonConfiguration())
}

/**
 * Represents an HTTP response where the status code is outside the range considered success.
 */
public class InvalidStatusException(s: String) : Exception(s)

/** Wraps an exception during resolution where the [DidResolutionMetadata.error] is not empty. */
public class ResolutionException(s: String) : Exception(s)

/**
 * Container for the key aliases for an ION did.
 */
public data class KeyAliases(
  public val updateKeyAlias: String,
  public val verificationKeyAlias: String,
  public val recoveryKeyAlias: String)

/**
 * Options available when creating an ion did.
 *
 * @param verificationPublicKey When provided, will be used as the verification key in the DID document.
 * @param updatePublicJWK When provided, will be used to create the update key commitment.
 * @param recoveryPublicJWK When provided, will be used to create the recovery key commitment.
 * @param verificationMethodId When provided, will be used as the verification method id. Cannot be over 50 chars and
 * must only use characters from the Base64URL character set.
 */
public class CreateDidIonOptions(
  public val verificationPublicKey: PublicKey? = null,
  public val updatePublicJWK: JWK? = null,
  public val recoveryPublicJWK: JWK? = null,
  public val verificationMethodId: String? = null,
) : CreateDidOptions

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