package web5.sdk.dids

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSAlgorithm
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
import org.erwinkok.multiformat.multicodec.Multicodec
import org.erwinkok.multiformat.multihash.Multihash
import org.erwinkok.result.get
import web5.dids.ion.model.AddPublicKeysAction
import web5.dids.ion.model.AddServicesAction
import web5.dids.ion.model.Commitment
import web5.dids.ion.model.Delta
import web5.dids.ion.model.Document
import web5.dids.ion.model.InitialState
import web5.dids.ion.model.OperationSuffixDataObject
import web5.dids.ion.model.PatchAction
import web5.dids.ion.model.PublicKey
import web5.dids.ion.model.PublicKeyPurpose
import web5.dids.ion.model.RemovePublicKeysAction
import web5.dids.ion.model.RemoveServicesAction
import web5.dids.ion.model.ReplaceAction
import web5.dids.ion.model.Reveal
import web5.dids.ion.model.Service
import web5.dids.ion.model.SidetreeCreateOperation
import web5.dids.ion.model.SidetreeUpdateOperation
import web5.dids.ion.model.UpdateOperationSignedData
import web5.sdk.crypto.KeyManager

private const val operationsPath = "/operations"
private const val identifiersPath = "/identifiers"

/**
 * Configuration for the DIDIonManager.
 *
 * @property ionHost The ION host URL.
 * @property engine The engine to use. When absent, a new one will be created from the [CIO] factory.
 */
public class DIDIonConfiguration internal constructor(
  public var ionHost: String = "https://ion.tbddev.org",
  public var engine: HttpClientEngine? = null,
)


/**
 * Returns a DIDIonManager after applying the provided configuration [builderAction].
 */
public fun DIDIonManager(builderAction: DIDIonConfiguration.() -> Unit): DIDIonManager {
  val conf = DIDIonConfiguration().apply(builderAction)
  return DIDIonManagerImpl(conf)
}

/** DIDIonCreator is sealed, so we provide an impl so the constructor can be called from the function above. */
private class DIDIonManagerImpl(configuration: DIDIonConfiguration) : DIDIonManager(configuration)

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
public class UpdateDidIonOptions(
  public val didString: String,
  public val updateKeyAlias: String,
  public val servicesToAdd: Iterable<Service>? = null,
  public val idsOfServicesToRemove: Set<String>? = null,
  public val publicKeysToAdd: Iterable<PublicKey>? = null,
  public val idsOfPublicKeysToRemove: Set<String>? = null,
) {
  internal fun toPatches(): List<PatchAction> {
    return buildList<PatchAction> {
      if (servicesToAdd != null) {
        add(AddServicesAction(servicesToAdd.toList()))
      }
      if (idsOfServicesToRemove != null) {
        add(RemoveServicesAction(idsOfServicesToRemove.toList()))
      }
      if (publicKeysToAdd != null) {
        add(AddPublicKeysAction(publicKeysToAdd.toList()))
      }
      if (idsOfPublicKeysToRemove != null) {
        add(RemovePublicKeysAction(idsOfPublicKeysToRemove.toList()))
      }
    }
  }
}

/**
 * Base class for managing DIDIon operations. Uses the given [configuration].
 */
public sealed class DIDIonManager(
  private val configuration: DIDIonConfiguration
) : DidMethod<CreateDidIonOptions> {

  private val mapper = jacksonObjectMapper()

  private val operationsEndpoint = configuration.ionHost + operationsPath
  private val identifiersEndpoint = configuration.ionHost + identifiersPath

  private val engine: HttpClientEngine = if (configuration.engine == null) {
    CIO.create {}
  } else {
    configuration.engine!!
  }

  private val client = HttpClient(engine) {
    install(ContentNegotiation) {
      jackson { mapper }
    }
  }

  override val method: String
    get() = "ion"

  /**
   * Creates a DID and DID Document.
   *
   * @return Pair of DID and DIDDocument.
   */
  override fun create(keyManager: KeyManager, options: CreateDidIonOptions?): Pair<Did, IonCreationMetadata> {
    val (createOp, keys) = createOperation(keyManager, options)

    val shortFormDIDSegment =
      Base64URL.encode(
        Multihash.sum(Multicodec.SHA2_256, canonicalized(createOp.suffixData)).get()?.bytes()
      ).toString()
    val initialState = InitialState(
      suffixData = createOp.suffixData,
      delta = createOp.delta,
    )
    val longFormDIDSegment = didUriSegment(initialState)

    val response: HttpResponse = runBlocking {
      client.post(operationsEndpoint) {
        contentType(ContentType.Application.Json)
        setBody(createOp)
      }
    }

    val opBody = runBlocking {
      response.bodyAsText()
    }
    if (response.status.value in 200..299) {
      val shortFormDID = "did:ion:$shortFormDIDSegment"
      val longFormDID = "$shortFormDID:$longFormDIDSegment"
      val resolutionResult = resolve(longFormDID)

      if (!resolutionResult.didResolutionMetadata.error.isNullOrEmpty()) {
        throw Exception("error when resolving after creation: ${resolutionResult.didResolutionMetadata.error}")
      }

      return Pair(
        Did(
          keyManager,
          resolutionResult.didDocument.id.toString()
        ),
        IonCreationMetadata(
          createOp,
          shortFormDID,
          longFormDID,
          opBody,
          keys
        )
      )
    }
    throw Exception("received error response '$opBody'")
  }

  private inline fun <reified T> canonicalized(data: T): ByteArray {
    val jsonString = mapper.writeValueAsString(data)
    return JsonCanonicalizer(jsonString).encodedUTF8
  }

  private inline fun <reified T> didUriSegment(initialState: T): String {
    val canonicalized = canonicalized(initialState)
    val longFormDIDSegment = Base64URL.encode(canonicalized).toString()
    return longFormDIDSegment
  }

  /**
   * Given a [didUrl], returns the [DidResolutionResult], which is specified in https://w3c-ccg.github.io/did-resolution/#did-resolution-result
   */
  override fun resolve(didUrl: String): DidResolutionResult {
    val did = DID.fromString(didUrl)
    require(did.methodName == "ion")

    val resp = runBlocking { client.get("$identifiersEndpoint/$did") }
    val body = runBlocking { resp.bodyAsText() }
    if (!resp.status.isSuccess()) {
      throw Exception("resolution error response '$body'")
    }
    return mapper.readValue(body, DidResolutionResult::class.java)
  }

  /**
   * Updates an ION did with the given [options]. The update key must be available in the [keyManager].
   */
  public fun update(keyManager: KeyManager, options: UpdateDidIonOptions): IonUpdateMetadata {
    val (updateOp, newUpdateKeyAlias) = createUpdateOperation(keyManager, options)
    val response: HttpResponse = runBlocking {
      client.post(operationsEndpoint) {
        contentType(ContentType.Application.Json)
        setBody(updateOp)
      }
    }
    val opBody = runBlocking { response.bodyAsText() }
    if (response.status.isSuccess()) {
      return IonUpdateMetadata(
        operationsResponseBody = opBody,
        updateKeyAlias = newUpdateKeyAlias,
      )
    }
    throw Exception("received error response '$opBody'")
  }

  private fun createUpdateOperation(keyManager: KeyManager, options: UpdateDidIonOptions):
    Pair<SidetreeUpdateOperation, String> {
    val updatePublicKey = keyManager.getPublicKey(options.updateKeyAlias)

    val newUpdateKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1)
    val newUpdatePublicKey = keyManager.getPublicKey(newUpdateKeyAlias)

    val (_, reveal) = publicKeyCommitment(updatePublicKey)
    val (commitment, _) = publicKeyCommitment(newUpdatePublicKey)

    val updateOpDeltaObject = Delta(
      patches = options.toPatches(),
      updateCommitment = commitment
    )

    val canonicalized = canonicalized(updateOpDeltaObject)
    val deltaHashBytes = Multihash.sum(Multicodec.SHA2_256, canonicalized).get()?.bytes()
    val deltaHash = Base64URL.encode(deltaHashBytes).toString()

    val payload = UpdateOperationSignedData(
      updateKey = updatePublicKey,
      deltaHash = deltaHash,
    )
    val jws = keyManager.sign(options.updateKeyAlias, Payload(mapper.writeValueAsString(payload)))
    val did = DID.fromString(options.didString)
    return Pair(
      SidetreeUpdateOperation(
        type = "update",
        didSuffix = did.methodSpecificId,
        revealValue = reveal,
        delta = updateOpDeltaObject,
        signedData = jws.serialize(false),
      ),
      newUpdateKeyAlias,
    )
  }

  private fun createOperation(keyManager: KeyManager, options: CreateDidIonOptions?)
    : Pair<SidetreeCreateOperation, KeyAliases> {
    val updatePublicJWK: JWK = if (options?.updatePublicJWK == null) {
      val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1)
      keyManager.getPublicKey(alias)
    } else {
      options.updatePublicJWK!!
    }
    val (publicKeyCommitment, _) = publicKeyCommitment(updatePublicJWK)

    val verificationPublicKey = if (options?.verificationPublicKey == null) {
      val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1)
      val verificationJWK = keyManager.getPublicKey(alias)
      PublicKey(
        id = "#${verificationJWK.keyID}}",
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
      val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1)
      keyManager.getPublicKey(alias)
    } else {
      options.recoveryPublicJWK!!
    }
    val (recoveryCommitment, _) = publicKeyCommitment(recoveryPublicJWK)

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

  private fun createOperationSuffixDataObject(
    createOperationDeltaObject: Delta,
    recoveryCommitment: String): OperationSuffixDataObject {
    val jsonString = mapper.writeValueAsString(createOperationDeltaObject)
    val canonicalized = JsonCanonicalizer(jsonString).encodedUTF8
    val deltaHashBytes = Multihash.sum(Multicodec.SHA2_256, canonicalized).get()?.bytes()
    val deltaHash = Base64URL.encode(deltaHashBytes).toString()
    return OperationSuffixDataObject(
      deltaHash = deltaHash,
      recoveryCommitment = recoveryCommitment
    )
  }

  private fun publicKeyCommitment(publicKeyJWK: JWK): Pair<Commitment, Reveal> {
    require(!publicKeyJWK.isPrivate)
    // 1. Encode the public key into the form of a valid JWK.
    val pkJson = publicKeyJWK.toJSONString()

    // 2. Canonicalize the JWK encoded public key using the implementation’s JSON_CANONICALIZATION_SCHEME.
    val canonicalized = JsonCanonicalizer(pkJson).encodedUTF8

    // 3. Use the implementation’s HASH_PROTOCOL to Multihash the canonicalized public key to generate the REVEAL_VALUE,
    val mh = Multihash.sum(Multicodec.SHA2_256, canonicalized).get()
    val reveal = Base64URL.encode(mh?.bytes()).toString()
    val intermediate = mh?.digest!!

    // then Multihash the resulting Multihash value again using the implementation’s HASH_PROTOCOL to produce
    // the public key commitment.
    val hashOfHash = Multihash.sum(Multicodec.SHA2_256, intermediate).get()?.bytes()
    return Pair(Base64URL.encode(hashOfHash).toString(), reveal)
  }

  /**
   * Default companion object for creating a DIDIonManager with a default configuration.
   */
  public companion object Default : DIDIonManager(DIDIonConfiguration())
}

/**
 * Metadata related to the update of an ion DID.
 */
public data class IonUpdateMetadata(
  public val operationsResponseBody: String,
  public val updateKeyAlias: String
)

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
 */
public class CreateDidIonOptions(
  public val verificationPublicKey: PublicKey? = null,
  public var updatePublicJWK: JWK? = null,
  public var recoveryPublicJWK: JWK? = null) : CreateDidOptions

/**
 * Metadata related to the creation of a DID (Decentralized Identifier) on the Sidetree protocol.
 *
 * @property createOperation The Sidetree create operation used to create the DID.
 * @property shortFormDID The short-form DID representing the DID created.
 * @property longFormDID The long-form DID representing the DID created.
 * @property operationsResponseBody The response body received after submitting the create operation.
 */
public data class IonCreationMetadata(
  public val createOperation: SidetreeCreateOperation,
  public val shortFormDID: String,
  public val longFormDID: String,
  public val operationsResponseBody: String,
  public val keyAliases: KeyAliases,
) : CreationMetadata