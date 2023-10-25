package web5.sdk.dids

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
import foundation.identity.did.VerificationMethod
import io.ipfs.multibase.Multibase
import web5.sdk.common.Varint
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.KeyManager
import web5.sdk.crypto.Secp256k1
import java.net.URI

/**
 * Specifies options for creating a new "did:key" Decentralized Identifier (DID).
 *
 * @property algorithm Specifies the algorithm to be used for key creation.
 *                     Defaults to ES256K (Elliptic Curve Digital Signature Algorithm with SHA-256 and secp256k1 curve).
 * @property curve Specifies the elliptic curve to be used with the algorithm.
 *                 Optional and can be null if the algorithm does not require an explicit curve specification.
 *
 * @constructor Creates an instance of [CreateDidKeyOptions] with the provided [algorithm] and [curve].
 *
 * ### Usage Example:
 * ```
 * val options = CreateDidKeyOptions(algorithm = JWSAlgorithm.ES256K, curve = null)
 * val didKey = DidKey.create(keyManager, options)
 * ```
 */
public class CreateDidKeyOptions(
  public val algorithm: Algorithm = JWSAlgorithm.ES256K,
  public val curve: Curve? = null
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
 * @constructor Initializes a new instance of [StatefulDidKey] with the provided [uri] and [keyManager].
 *
 * ### Usage Example:
 * ```kotlin
 * val keyManager = InMemoryKeyManager()
 * val did = DidKey("did:key:example", keyManager)
 * ```
 */
public class StatefulDidKey(uri: String, keyManager: KeyManager) : StatefulDid(uri, keyManager) {
  /**
   * Resolves the current instance's [uri] to a [DidResolutionResult], which contains the DID Document
   * and possible related metadata.
   *
   * @return A [DidResolutionResult] instance containing the DID Document and related context.
   *
   * @throws IllegalArgumentException if the provided DID does not conform to the "did:key" method.
   */
  public fun resolve(): DidResolutionResult {
    return DidKeyApi.resolve(this.uri)
  }
}

/**
 * API for interacting with "did:key" DIDS.
 *
 * ### Usage Example:
 * ```kotlin
 * val keyManager = InMemoryKeyManager()
 * val did = DidKeyApi.create()
 * ```
 */
public open class DidKeyApi : DidMethod<StatefulDidKey, CreateDidKeyOptions> {
  override val methodName: String = "key"

  /**
   * Creates a new "did:key" DID, derived from a public key, and stores the associated private key in the
   * provided [KeyManager].
   *
   * The method-specific identifier of a "did:key" DID is a multibase encoded public key.
   *
   * **Note**: Defaults to ES256K if no options are provided
   *
   * @param keyManager A [KeyManager] instance where the new key will be stored.
   * @param options Optional parameters ([CreateDidKeyOptions]) to specify algorithm and curve during key creation.
   * @return A [StatefulDidKey] instance representing the newly created "did:key" DID.
   *
   * @throws UnsupportedOperationException if the specified curve is not supported.
   */
  override fun create(keyManager: KeyManager, options: CreateDidKeyOptions?): StatefulDidKey {
    val opts = options ?: CreateDidKeyOptions()

    val keyAlias = keyManager.generatePrivateKey(opts.algorithm, opts.curve)
    val publicKey = keyManager.getPublicKey(keyAlias)
    var publicKeyBytes = Crypto.publicKeyToBytes(publicKey)

    if (opts.algorithm == JWSAlgorithm.ES256K) {
      publicKeyBytes = Secp256k1.compressPublicKey(publicKeyBytes)
    }

    val multiCodec = Crypto.getAlgorithmMultiCodec(opts.algorithm, opts.curve)
      ?: throw UnsupportedOperationException("${opts.curve} curve not supported")

    val multiCodecBytes = Varint.encode(multiCodec)
    val idBytes = multiCodecBytes + publicKeyBytes
    val multibaseEncodedId = Multibase.encode(Multibase.Base.Base58BTC, idBytes)

    val did = "did:key:$multibaseEncodedId"

    return StatefulDidKey(did, keyManager)
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
  override fun resolve(did: String, options: ResolveDidOptions?): DidResolutionResult {
    val parsedDid = DID.fromString(did)

    require(parsedDid.methodName == methodName) { throw IllegalArgumentException("expected did:key") }

    val id = parsedDid.methodSpecificId
    val idBytes = Multibase.decode(id)
    val (multiCodec, numBytes) = Varint.decode(idBytes)

    var publicKeyBytes = idBytes.drop(numBytes).toByteArray()
    val keyGenerator = Crypto.getKeyGenerator(multiCodec)

    if (keyGenerator.algorithm == Secp256k1.algorithm) {
      publicKeyBytes = Secp256k1.inflatePublicKey(publicKeyBytes)
    }

    val publicKeyJwk = keyGenerator.bytesToPublicKey(publicKeyBytes)

    val verificationMethodId = URI.create("$did#$id")
    val verificationMethod = VerificationMethod.builder()
      .id(verificationMethodId)
      .publicKeyJwk(publicKeyJwk.toJSONObject())
      .controller(URI(did))
      .type("JsonWebKey2020")
      .build()

    val verificationMethodRef = VerificationMethod.builder()
      .id(verificationMethodId)
      .build()

    val didDocument = DIDDocument.builder()
      .id(URI(did))
      .verificationMethod(verificationMethod)
      .assertionMethodVerificationMethod(verificationMethodRef)
      .authenticationVerificationMethod(verificationMethodRef)
      .capabilityDelegationVerificationMethods(listOf(verificationMethodRef))
      .capabilityInvocationVerificationMethod(verificationMethodRef)
      .keyAgreementVerificationMethod(verificationMethodRef)
      .build()

    return DidResolutionResult(didDocument = didDocument, context = "https://w3id.org/did-resolution/v1")
  }

  /**
   * Default companion object for creating a [DidKeyApi] with a default configuration.
   */
  public companion object Default : DidKeyApi()
}