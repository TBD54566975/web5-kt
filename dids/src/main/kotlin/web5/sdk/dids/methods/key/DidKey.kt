package web5.sdk.dids.methods.key

import io.ipfs.multibase.Multibase
import web5.sdk.common.Varint
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.KeyManager
import web5.sdk.crypto.Secp256k1
import web5.sdk.dids.CreateDidOptions
import web5.sdk.dids.ChangemeDid
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.ResolveDidOptions
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.didcore.DIDDocument
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.didcore.VerificationMethod

/**
 * Specifies options for creating a new "did:key" Decentralized Identifier (DID).
 *
 * @property algorithmId Specifies the algorithmId to be used for key creation.
 *                       Defaults to ES256K (Elliptic Curve Digital Signature Algorithm with SHA-256 and secp256k1 curve).
 * @constructor Creates an instance of [CreateDidKeyOptions] with the provided [algorithmId].
 *
 * ### Usage Example:
 * ```
 * val options = CreateDidKeyOptions(algorithm = JWSAlgorithm.ES256K, curve = null)
 * val didKey = DidKey.create(keyManager, options)
 * ```
 */
public class CreateDidKeyOptions(
  public val algorithmId: AlgorithmId = AlgorithmId.secp256k1,
) : CreateDidOptions

/**
 * Provides a specific implementation for creating and resolving "did:key" method Decentralized Identifiers (DIDs).
 *
 * A "did:key" DID is a special type of DID that is formulated directly from a single public key. It's utilized
 * in scenarios where it's beneficial for verifiable credentials, capabilities, or other assertions about a subject
 * to be self-verifiable by third parties. This eradicates the necessity for a separate blockchain or ledger.
 * Further specifics and technical details are outlined in [the DID Key Spec](https://w3c-ccg.github.io/did-method-key/).
 *
 * @property uri The URI of the "did:key" which conforms to the DID standard.
 * @property keyManager A [KeyManager] instance utilized to manage the cryptographic keys associated with the DID.
 *
 * @constructor Initializes a new instance of [DidKey] with the provided [uri] and [keyManager].
 */
public class DidKey(uri: String, keyManager: KeyManager) : ChangemeDid(uri, keyManager) {
  /**
   * Resolves the current instance's [uri] to a [DidResolutionResult], which contains the DID Document
   * and possible related metadata.
   *
   * @return A [DidResolutionResult] instance containing the DID Document and related context.
   *
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:key" method.
   */
  public fun resolve(): DidResolutionResult {
    return resolve(this.uri, null)
  }

  public companion object {
    public val methodName: String = "key"

    /**
     * Creates a new "did:key" DID, derived from a public key, and stores the associated private key in the
     * provided [KeyManager].
     *
     * The method-specific identifier of a "did:key" DID is a multibase encoded public key.
     *
     * **Note**: Defaults to ES256K if no options are provided
     *
     * @param keyManager A [KeyManager] instance where the new key will be stored.
     * @param options Optional parameters ([CreateDidKeyOptions]) to specify algorithmId during key creation.
     * @return A [DidKey] instance representing the newly created "did:key" DID.
     *
     * @throws UnsupportedOperationException if the specified curve is not supported.
     */
    public fun create(keyManager: KeyManager, options: CreateDidKeyOptions?): DidKey {
      val opts = options ?: CreateDidKeyOptions()

      val keyAlias = keyManager.generatePrivateKey(opts.algorithmId)
      val publicKey = keyManager.getPublicKey(keyAlias)
      var publicKeyBytes = Crypto.publicKeyToBytes(publicKey)

      if (opts.algorithmId == AlgorithmId.secp256k1) {
        publicKeyBytes = Secp256k1.compressPublicKey(publicKeyBytes)
      }

      val multiCodec = Crypto.getAlgorithmMultiCodec(opts.algorithmId)
        ?: throw UnsupportedOperationException("${opts.algorithmId.curveName} curve not supported")

      val multiCodecBytes = Varint.encode(multiCodec)
      val idBytes = multiCodecBytes + publicKeyBytes
      val multibaseEncodedId = Multibase.encode(Multibase.Base.Base58BTC, idBytes)

      val did = "did:key:$multibaseEncodedId"

      return DidKey(did, keyManager)
    }

    /**
     * Resolves a "did:key" DID into a [DidResolutionResult], which contains the DID Document and possible related metadata.
     *
     * This implementation primarily constructs a DID Document with a single verification method derived
     * from the DID's method-specific identifier (the public key).
     *
     * @param did The "did:key" DID that needs to be resolved.
     * @return A [DidResolutionResult] instance containing the DID Document and related context.
     *
     * @throws IllegalArgumentException if the provided DID does not conform to the "did:key" method.
     */
    public fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
      val parsedDid = Did.parse(did)

      require(parsedDid.method == methodName) { throw IllegalArgumentException("expected did:key") }

      val id = parsedDid.id
      val idBytes = Multibase.decode(id)
      val (multiCodec, numBytes) = Varint.decode(idBytes)

      var publicKeyBytes = idBytes.drop(numBytes).toByteArray()
      val keyGenerator = Crypto.getKeyGenerator(multiCodec)

      if (keyGenerator.algorithm == Secp256k1.algorithm) {
        publicKeyBytes = Secp256k1.inflatePublicKey(publicKeyBytes)
      }

      val publicKeyJwk = keyGenerator.bytesToPublicKey(publicKeyBytes)

      val verificationMethodId = "${parsedDid.uri}#$id"
      val verificationMethod = VerificationMethod.Builder()
        .id(verificationMethodId)
        .publicKeyJwk(publicKeyJwk)
        .controller(did)
        .type("JsonWebKey2020")
        .build()

      val didDocument = DIDDocument.Builder()
        .id(did)
        .verificationMethodForPurposes(
          verificationMethod,
          listOf(
            Purpose.AssertionMethod,
            Purpose.Authentication,
            Purpose.KeyAgreement,
            Purpose.CapabilityDelegation,
            Purpose.CapabilityInvocation
          ))
        .build()

      return DidResolutionResult(didDocument = didDocument, context = "https://w3id.org/did-resolution/v1")
    }
  }
}

