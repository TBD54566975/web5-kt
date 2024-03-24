package web5.sdk.dids.methods.key

import io.ipfs.multibase.Multibase
import org.apache.http.MethodNotSupportedException
import web5.sdk.common.Varint
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.KeyManager
import web5.sdk.crypto.Secp256k1
import web5.sdk.dids.CreateDidOptions
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.did.BearerDid
import web5.sdk.dids.did.PortableDid
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.didcore.DidDocument
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.didcore.VerificationMethod
import web5.sdk.dids.exceptions.InvalidMethodNameException

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
  public val algorithmId: AlgorithmId = AlgorithmId.Ed25519,
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
public class DidKey(public val uri: String, public val keyManager: KeyManager) {
  /**
   * Resolves the current instance's [uri] to a [DidResolutionResult], which contains the DID Document
   * and possible related metadata.
   *
   * @return A [DidResolutionResult] instance containing the DID Document and related context.
   *
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:key" method.
   */
  public fun resolve(): DidResolutionResult {
    return resolve(this.uri)
  }

  public companion object {
    public const val methodName: String = "key"

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
    @JvmOverloads
    public fun create(keyManager: KeyManager, options: CreateDidKeyOptions? = null): BearerDid {
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

      val didUrl = "did:key:$multibaseEncodedId"

      val did = Did(method = methodName, uri = didUrl, url = didUrl, id = multibaseEncodedId)
      val resolutionResult = resolve(didUrl)
      check(resolutionResult.didDocument != null) {
        "DidDocument not found"
      }
      return BearerDid(didUrl, did, keyManager, resolutionResult.didDocument)
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
    public fun resolve(did: String): DidResolutionResult {
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

      val didDocument = DidDocument.Builder()
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

    /**
     * Instantiates a [BearerDid] object for the DID KEY method from a given [PortableDid].
     *
     * This method allows for the creation of a `BearerDid` object using a previously created DID's
     * key material, DID document, and metadata.
     *
     * @param portableDid - The PortableDid object to import.
     * @param keyManager - Optionally specify an external Key Management System (KMS) used to
     *                            generate keys and sign data. If not given, a new
     *                            [InMemoryKeyManager] instance will be created and
     *                            used.
     * @returns a BearerDid object representing the DID formed from the
     *          provided PortableDid.
     * @throws InvalidMethodNameException if importing incorrect DID method
     */
    @JvmOverloads
    public fun import(portableDid: PortableDid, keyManager: KeyManager = InMemoryKeyManager()): BearerDid {
      val parsedDid = Did.parse(portableDid.uri)
      if (parsedDid.method != methodName) {
        throw InvalidMethodNameException("Method not supported")
      }

      val bearerDid = BearerDid.import(portableDid, keyManager)

      check(bearerDid.document.verificationMethod?.size == 1) {
        "DidKey DID document must contain exactly one verification method"
      }

      return bearerDid
    }
  }
}

