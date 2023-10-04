package web5.dids

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
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
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.erdtman.jcs.JsonCanonicalizer
import org.erwinkok.multiformat.multicodec.Multicodec
import org.erwinkok.multiformat.multihash.Multihash
import org.erwinkok.result.get
import uniresolver.result.ResolveDataModelResult
import uniresolver.result.ResolveRepresentationResult
import web5.dids.ion.model.Commitment
import web5.dids.ion.model.Delta
import web5.dids.ion.model.Document
import web5.dids.ion.model.InitialState
import web5.dids.ion.model.JsonWebKey
import web5.dids.ion.model.OperationSuffixDataObject
import web5.dids.ion.model.PublicKey
import web5.dids.ion.model.PublicKeyPurpose
import web5.dids.ion.model.ReplaceAction
import web5.dids.ion.model.SidetreeCreateOperation
import web5.dids.ion.model.toJWK
import web5.dids.ion.model.toJsonWebKey
import java.security.Provider
import java.util.UUID

private const val operationsPath = "/operations"
private const val identifiersPath = "/identifiers"

/**
 * Configuration for the DIDIonManager.
 *
 * @property ionHost The ION host URL.
 * @property updatePublicJsonWebKey The update public JSON Web Key. When absent, a new one will be generated.
 * @property verificationPublicKey The verification public key. When absent, a new one will be generated.
 * @property recoveryJsonWebKey The recovery JSON Web Key. When absent, a new one will be generated.
 * @property engine The engine to use. When absent, a new one will be created from the [CIO] factory.
 */
public class DIDIonConfiguration internal constructor(
  public var ionHost: String = "https://ion.tbddev.org",
  public var updatePublicJsonWebKey: JsonWebKey? = null,
  public var verificationPublicKey: PublicKey? = null,
  public var recoveryJsonWebKey: JsonWebKey? = null,
  public var engine: HttpClientEngine? = null,
)


/**
 * Returns a DIDIonManager with the provided configuration [block].
 */
public fun DIDIonManager(block: DIDIonConfiguration.() -> Unit): DIDIonManager {
  val conf = DIDIonConfiguration().apply(block)
  return DIDIonManagerImpl(conf)
}

/** DIDIonCreator is sealed, so we provide an impl so the constructor can be called from the function above. */
private class DIDIonManagerImpl(configuration: DIDIonConfiguration) : DIDIonManager(configuration)

/**
 * Base class for managing DIDIon operations. Uses the given [configuration].
 */
public sealed class DIDIonManager(
  public val configuration: DIDIonConfiguration
) {

  @OptIn(ExperimentalSerializationApi::class)
  private val json = Json {
    prettyPrint = true
    explicitNulls = false
  }

  private val operationsEndpoint = configuration.ionHost + operationsPath
  private val identifiersEndpoint = configuration.ionHost + identifiersPath

  private val engine: HttpClientEngine = if (configuration.engine == null) {
    CIO.create {}
  } else {
    configuration.engine!!
  }

  private val client = HttpClient(engine) {
    install(ContentNegotiation) {
      json(json)
    }
  }

  /**
   * Creates a DID and DID Document.
   *
   * @return Pair of DID and DIDDocument.
   */
  public suspend fun create(): Triple<DID, DIDDocument, CreationMetadata> {
    val createOp = createOperation()

    val shortFormDIDSegment =
      Base64URL.encode(
        Multihash.sum(Multicodec.SHA2_256, canonicalized(createOp.suffixData)).get()?.bytes()
      ).toString()
    val initialState = InitialState(
      suffixData = createOp.suffixData,
      delta = createOp.delta,
    )
    val longFormDIDSegment = didUriSegment(initialState)

    val response: HttpResponse = client.post(operationsEndpoint) {
      contentType(ContentType.Application.Json)
      setBody(createOp)
    }

    val opBody = response.bodyAsText()
    if (response.status.value in 200..299) {
      val shortFormDID = "did:ion:$shortFormDIDSegment"
      val longFormDID = "$shortFormDID:$longFormDIDSegment"
      val resolutionResponse = client.get("$identifiersEndpoint/$longFormDID")
      val body = resolutionResponse.bodyAsText()

      if (resolutionResponse.status.value in 200..299) {
        val (did, didDocument) = parseResult(body)
        return Triple(
          did, didDocument,
          CreationMetadata(
            createOp,
            shortFormDID,
            longFormDID,
            opBody
          )
        )
      }
      throw Exception("received error response '$body'")
    }
    throw Exception("received error response '$opBody'")
  }

  private inline fun <reified T> canonicalized(data: T): ByteArray {
    val jsonString = json.encodeToString(data)
    return JsonCanonicalizer(jsonString).encodedUTF8
  }

  private inline fun <reified T> didUriSegment(initialState: T): String {
    val canonicalized = canonicalized(initialState)
    val longFormDIDSegment = Base64URL.encode(canonicalized).toString()
    return longFormDIDSegment
  }

  /**
   * Given a [did], returns the [ResolveRepresentationResult], which is specified in https://w3c-ccg.github.io/did-resolution/#did-resolution-result
   */
  public suspend fun resolve(did: DID): ResolveDataModelResult {
    require(did.methodName == "ion")

    val resp = client.get(
      "https://ion.tbddev.org/identifiers/$did"
    )
    val body = resp.bodyAsText()
    val mapper = jacksonObjectMapper()
    return mapper.readValue(body, ResolveDataModelResult::class.java)
  }

  private fun parseResult(resolutionResult: String): Pair<DID, DIDDocument> {
    val mapper = jacksonObjectMapper()
    val resolution = mapper.readValue(resolutionResult, ResolveDataModelResult::class.java)
    return Pair(DID.fromUri(resolution!!.didDocument.id), resolution.didDocument)
  }

  private fun createOperation(): SidetreeCreateOperation {
    val updatePublicJWK: JWK = if (configuration.updatePublicJsonWebKey == null) {
      val updateKeyID = UUID.randomUUID().toString()
      val updateJWK: ECKey = secp256KeyWithID(updateKeyID)
      updateJWK.toPublicJWK()
    } else {
      configuration.updatePublicJsonWebKey!!.toJWK()
    }
    val publicKeyCommitment: String = publicKeyCommitment(updatePublicJWK)

    val verificationPublicKey = if (configuration.verificationPublicKey == null) {
      val verificationKeyID = UUID.randomUUID().toString()
      val verificationJWK = secp256KeyWithID(verificationKeyID)
      PublicKey(
        id = verificationKeyID,
        type = "JsonWebKey2020",
        publicKeyJWK = verificationJWK.toJsonWebKey(),
        purposes = listOf(PublicKeyPurpose.AUTHENTICATION),
      )
    } else {
      configuration.verificationPublicKey!!
    }
    val patches = listOf(ReplaceAction(Document(listOf(verificationPublicKey))))
    val createOperationDelta = Delta(
      patches = patches,
      updateCommitment = publicKeyCommitment
    )

    val recoveryKeyID = UUID.randomUUID().toString()
    val recoveryJWK: ECKey = secp256KeyWithID(recoveryKeyID)
    val recoveryCommitment = publicKeyCommitment(recoveryJWK.toPublicJWK())

    val operation: OperationSuffixDataObject =
      createOperationSuffixDataObject(createOperationDelta, recoveryCommitment)

    return SidetreeCreateOperation(
      type = "create",
      suffixData = operation,
      delta = createOperationDelta,
    )
  }

  private fun secp256KeyWithID(recoveryKeyID: String): ECKey = ECKeyGenerator(Curve.SECP256K1)
    .keyUse(KeyUse.SIGNATURE)
    .keyID(recoveryKeyID)
    .provider(BouncyCastleProviderSingleton.getInstance() as Provider)
    .generate()

  private fun createOperationSuffixDataObject(
    createOperationDeltaObject: Delta,
    recoveryCommitment: String): OperationSuffixDataObject {
    val jsonString = json.encodeToString(createOperationDeltaObject)
    val canonicalized = JsonCanonicalizer(jsonString).encodedUTF8
    val deltaHash = Multihash.sum(Multicodec.SHA2_256, canonicalized).get()?.bytes()
    return OperationSuffixDataObject(
      deltaHash = Base64URL.encode(deltaHash).toString(),
      recoveryCommitment = recoveryCommitment
    )
  }

  private fun publicKeyCommitment(publicKeyJWK: JWK): Commitment {
    require(!publicKeyJWK.isPrivate)
    // 1. Encode the public key into the form of a valid JWK.
    val pkJson = publicKeyJWK.toJSONString()

    // 2. Canonicalize the JWK encoded public key using the implementation’s JSON_CANONICALIZATION_SCHEME.
    val canonicalized = JsonCanonicalizer(pkJson).encodedUTF8

    // 3. Use the implementation’s HASH_PROTOCOL to Multihash the canonicalized public key to generate the REVEAL_VALUE,
    val intermediate = Multihash.sum(Multicodec.SHA2_256, canonicalized).get()?.digest!!

    // then Multihash the resulting Multihash value again using the implementation’s HASH_PROTOCOL to produce
    // the public key commitment.
    val hashOfHash = Multihash.sum(Multicodec.SHA2_256, intermediate).get()?.bytes()
    return Base64URL.encode(hashOfHash).toString()
  }

  /**
   * Default companion object for creating a DIDIonManager with a default configuration.
   */
  public companion object Default : DIDIonManager(DIDIonConfiguration())
}

/**
 * Metadata related to the creation of a DID (Decentralized Identifier) on the Sidetree protocol.
 *
 * @property createOperation The Sidetree create operation used to create the DID.
 * @property shortFormDID The short-form DID representing the DID created.
 * @property longFormDID The long-form DID representing the DID created.
 * @property operationsResponseBody The response body received after submitting the create operation.
 */
public data class CreationMetadata(
  public val createOperation: SidetreeCreateOperation,
  public val shortFormDID: String,
  public val longFormDID: String,
  public val operationsResponseBody: String
)