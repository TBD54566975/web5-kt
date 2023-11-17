package web5.sdk.dids.methods.jwk

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
import foundation.identity.did.VerificationMethod
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.CreateDidOptions
import web5.sdk.dids.Did
import web5.sdk.dids.DidMethod
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.ResolveDidOptions
import web5.sdk.dids.validateKeyMaterialInsideKeyManager
import java.net.URI

/**
 * Specifies options for creating a new "did:jwk" Decentralized Identifier (DID).
 *
 * @property algorithm Specifies the algorithm to be used for key creation.
 *                     Defaults to ES256K (Elliptic Curve Digital Signature Algorithm with SHA-256 and secp256k1 curve).
 * @property curve Specifies the elliptic curve to be used with the algorithm.
 *                 Optional and can be null if the algorithm does not require an explicit curve specification.
 *
 * @constructor Creates an instance of [CreateDidJwkOptions] with the provided [algorithm] and [curve].
 *
 * ### Usage Example:
 * ```
 * val options = CreateDidJwkOptions(algorithm = JWSAlgorithm.ES256K, curve = null)
 * val didJwk = DidJwk.create(keyManager, options)
 * ```
 */
public class CreateDidJwkOptions(
  public val algorithm: Algorithm = JWSAlgorithm.ES256K,
  public val curve: Curve? = null
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
public class DidJwk private constructor(uri: String, keyManager: KeyManager) : Did(uri, keyManager) {
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
     * @param options Optional parameters ([CreateDidJwkOptions]) to specify algorithm and curve during key creation.
     * @return A [DidJwk] instance representing the newly created "did:jwk" DID.
     *
     * @throws UnsupportedOperationException if the specified curve is not supported.
     */
    override fun create(keyManager: KeyManager, options: CreateDidJwkOptions?): DidJwk {
      val opts = options ?: CreateDidJwkOptions()

      val keyAlias = keyManager.generatePrivateKey(opts.algorithm, opts.curve)
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
      val parsedDid = DID.fromString(did)

      require(parsedDid.methodName == methodName) { throw IllegalArgumentException("expected did:jwk") }

      val id = parsedDid.methodSpecificId
      val decodedKey = Convert(id, EncodingFormat.Base64Url).toStr()
      val publicKeyJwk = JWK.parse(decodedKey)

      require(!publicKeyJwk.isPrivate) {
        throw IllegalArgumentException("decoded jwk value cannot be a private key")
      }

      val verificationMethodId = URI.create("$did#0")
      val verificationMethod = VerificationMethod.builder()
        .id(verificationMethodId)
        .publicKeyJwk(publicKeyJwk.toJSONObject())
        .controller(URI(did))
        .type("JsonWebKey2020")
        .build()

      val verificationMethodRef = VerificationMethod.builder()
        .id(verificationMethodId)
        .build()

      val didDocumentBuilder = DIDDocument.builder()
        .contexts(
          mutableListOf(
            URI.create("https://w3id.org/security/suites/jws-2020/v1")
          )
        )
        .id(URI(did))
        .verificationMethod(verificationMethod)

      if (publicKeyJwk.keyUse != KeyUse.ENCRYPTION) {
        didDocumentBuilder
          .assertionMethodVerificationMethod(verificationMethodRef)
          .authenticationVerificationMethod(verificationMethodRef)
          .capabilityDelegationVerificationMethods(listOf(verificationMethodRef))
          .capabilityInvocationVerificationMethod(verificationMethodRef)
      }
      if (publicKeyJwk.keyUse != KeyUse.SIGNATURE) {
        didDocumentBuilder.keyAgreementVerificationMethod(verificationMethodRef)
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
