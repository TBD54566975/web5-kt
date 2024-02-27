package web5.sdk.dids.methods.jwk

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.CreateDidOptions
import web5.sdk.dids.Did
import web5.sdk.dids.DidMethod
import web5.sdk.dids.DidResolutionMetadata
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.ResolutionError
import web5.sdk.dids.ResolveDidOptions
import web5.sdk.dids.didcore.DidUri
import web5.sdk.dids.didcore.DIDDocument
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.didcore.VerificationMethod
import web5.sdk.dids.exceptions.ParserException
import web5.sdk.dids.validateKeyMaterialInsideKeyManager
import java.text.ParseException

/**
 * Specifies options for creating a new "did:jwk" Decentralized Identifier (DID).
 *
 * @property algorithmId Specifies the algorithmId to be used for key creation.
 *                     Defaults to ES256K (Elliptic Curve Digital Signature Algorithm with SHA-256 and secp256k1 curve).
 * @constructor Creates an instance of [CreateDidJwkOptions] with the provided [algorithmId]
 *
 * ### Usage Example:
 * ```
 * val options = CreateDidJwkOptions(algorithm = JWSAlgorithm.ES256K, curve = null)
 * val didJwk = DidJwk.create(keyManager, options)
 * ```
 */
public class CreateDidJwkOptions(
  public val algorithmId: AlgorithmId = AlgorithmId.secp256k1,
) : CreateDidOptions

/**
 * Provides a specific implementation for creating and resolving "did:jwk" method Decentralized Identifiers (DIDs).
 *
 * A "did:jwk" DID is a special type of DID that is formulated directly from a single public key. It's utilized
 * in scenarios where it's beneficial for verifiable credentials, capabilities, or other assertions about a subject
 * to be self-verifiable by third parties. This eradicates the necessity for a separate blockchain or ledger.
 * Further specifics and technical details are outlined in [the DID Jwk Spec](https://example.org/did-method-jwk/).
 *
 * @property uri The URI of the "did:jwk" which conforms to the DID standard.
 * @property keyManager A [KeyManager] instance utilized to manage the cryptographic keys associated with the DID.
 *
 * @constructor Initializes a new instance of [DidJwk] with the provided [uri] and [keyManager].
 */
public class DidJwk(uri: String, keyManager: KeyManager) : Did(uri, keyManager) {
  /**
   * Resolves the current instance's [uri] to a [DidResolutionResult], which contains the DID Document
   * and possible related metadata.
   *
   * @return A [DidResolutionResult] instance containing the DID Document and related context.
   *
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:jwk" method.
   */
  public fun resolve(): DidResolutionResult {
    return resolve(this.uri)
  }

  public companion object : DidMethod<DidJwk, CreateDidJwkOptions> {
    override val methodName: String = "jwk"

    /**
     * Creates a new "did:jwk" DID, derived from a public key, and stores the associated private key in the
     * provided [KeyManager].
     *
     * The method-specific identifier of a "did:jwk" DID is a base64url encoded json web key serialized as a UTF-8
     * string.
     *
     * **Note**: Defaults to ES256K if no options are provided
     *
     * @param keyManager A [KeyManager] instance where the new key will be stored.
     * @param options Optional parameters ([CreateDidJwkOptions]) to specify algorithmId during key creation.
     * @return A [DidJwk] instance representing the newly created "did:jwk" DID.
     *
     * @throws UnsupportedOperationException if the specified curve is not supported.
     */
    override fun create(keyManager: KeyManager, options: CreateDidJwkOptions?): DidJwk {
      val opts = options ?: CreateDidJwkOptions()

      val keyAlias = keyManager.generatePrivateKey(opts.algorithmId)
      val publicKey = keyManager.getPublicKey(keyAlias)

      val base64Encoded = Convert(publicKey.toJSONString()).toBase64Url(padding = false)

      val did = "did:jwk:$base64Encoded"

      return DidJwk(did, keyManager)
    }

    /**
     * Resolves a "did:jwk" DID into a [DidResolutionResult], which contains the DID Document and possible related metadata.
     *
     * This implementation primarily constructs a DID Document with a single verification method derived
     * from the DID's method-specific identifier (the public key).
     *
     * @param did The "did:jwk" DID that needs to be resolved.
     * @return A [DidResolutionResult] instance containing the DID Document and related context.
     *
     * @throws IllegalArgumentException if the provided DID does not conform to the "did:jwk" method.
     */
    override fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
      val parsedDidUri = try {
        DidUri.parse(did)
      } catch (_: ParserException) {
        return DidResolutionResult(
          context = "https://w3id.org/did-resolution/v1",
          didResolutionMetadata = DidResolutionMetadata(
            error = ResolutionError.INVALID_DID.value,
          ),
        )
      }

      if (parsedDidUri.method != methodName) {
        return DidResolutionResult(
          context = "https://w3id.org/did-resolution/v1",
          didResolutionMetadata = DidResolutionMetadata(
            error = ResolutionError.METHOD_NOT_SUPPORTED.value,
          ),
        )
      }

      val id = parsedDidUri.id
      val decodedKey = Convert(id, EncodingFormat.Base64Url).toStr()
      val publicKeyJwk = try {
        JWK.parse(decodedKey)
      } catch (_: ParseException) {
        return DidResolutionResult(
          context = "https://w3id.org/did-resolution/v1",
          didResolutionMetadata = DidResolutionMetadata(
            error = ResolutionError.INVALID_DID.value
          )
        )
      }

      require(!publicKeyJwk.isPrivate) {
        throw IllegalArgumentException("decoded jwk value cannot be a private key")
      }

      val verificationMethodId = "$did#0"
      val verificationMethod = VerificationMethod.builder()
        .id(verificationMethodId)
        .publicKeyJwk(publicKeyJwk)
        .controller(did)
        .type("JsonWebKey2020")
        .build()

      val didDocumentBuilder = DIDDocument.Builder()
        .context("https://www.w3.org/ns/did/v1")
        .id(did)

      if (publicKeyJwk.keyUse != KeyUse.ENCRYPTION) {
        didDocumentBuilder
          .verificationMethodForPurposes(
            verificationMethod,
            listOf(
              Purpose.AssertionMethod,
              Purpose.Authentication,
              Purpose.CapabilityDelegation,
              Purpose.CapabilityInvocation
            )
          )
      }
      // todo do we want to add verificationMethod again here?
      if (publicKeyJwk.keyUse != KeyUse.SIGNATURE) {
        didDocumentBuilder.verificationMethodForPurposes(verificationMethod, listOf(Purpose.KeyAgreement))
      }
      val didDocument = didDocumentBuilder.build()

      return DidResolutionResult(didDocument = didDocument, context = "https://w3id.org/did-resolution/v1")
    }


    /**
     * Instantiates a [DidJwk] instance from [uri] (which has to start with "did:jwk:"), and validates that the
     * associated key material exists in the provided [keyManager].
     *
     * ### Usage Example:
     * ```kotlin
     * val keyManager = InMemoryKeyManager()
     * val did = DidJwk.load("did:jwk:example", keyManager)
     * ```
     */
    override fun load(uri: String, keyManager: KeyManager): DidJwk {
      validateKeyMaterialInsideKeyManager(uri, keyManager)
      return DidJwk(uri, keyManager)
    }
  }
}
