package web5.sdk.dids

import web5.sdk.crypto.KeyManager

/**
 * Represents options during the creation of a Decentralized Identifier (DID).
 *
 * Implementations of this interface may contain properties and methods that provide
 * specific options or metadata during the DID creation processes following specific
 * DID method specifications.
 *
 * ### Usage Example:
 * Implement this interface in classes where specific creation options are needed
 * for different DID methods.
 *
 * ```
 * class MyDidCreationOptions : CreateDidOptions {
 *     // Implementation-specific options for DID creation.
 * }
 * ```
 */
public interface CreateDidOptions

/**
 * Represents metadata that results from the creation of a Decentralized Identifier (DID).
 *
 * Implementers can include information that would be considered useful for callers.
 *
 * ### Usage Example
 * ```
 * class MyDidMethodCreatedMetadata : CreationMetadata {
 *     // implementation-specific metadata about the created did
 * }
 * ```
 */
public interface CreationMetadata

/**
 * Represents a Decentralized Identifier (DID) as per the W3C DID specification.
 *
 * A DID is a new type of identifier that is created, resolved, and cryptographically
 * verified in a decentralized manner, commonly via blockchain technology.
 *
 * @property keyManager Reference to a [KeyManager] instance to manage cryptographic keys related to this DID.
 * @property uri The string representation of the DID in URI format.
 *
 * ### Example Usage:
 * ```
 * val myDid = Did(myKeyManager, "did:example:123456789abcdefghi")
 * ```
 */
public open class Did(
  public val keyManager: KeyManager,
  public val uri: String
)

/**
 * Defines the contract for DID methods, facilitating creation and resolution of DIDs.
 *
 * A DID method specifies how a DID is placed on a specific blockchain or network (its 'namespace'),
 * and how it is created, resolved, updated, and revoked on that blockchain or network.
 *
 * @property method A string that defines the method to manage the DID (e.g., "btcr" for Bitcoin, "ethr" for Ethereum).
 * @param T The specific type of options required during the DID creation, adhering to [CreateDidOptions].
 *
 * ### Usage Example:
 * Implement this interface in classes that facilitate a specific method of handling DIDs on
 * particular blockchains or networks.
 *
 * ```
 * class MyDidMethod : DidMethod<MyDidCreationOptions> {
 *     override val method = "myMethod"
 *
 *     override fun create(keyManager: KeyManager, options: MyDidCreationOptions?): Did {
 *         //...Implementation details...
 *     }
 *
 *     override fun resolve(didUrl: String): DidResolutionResult {
 *         //...Implementation details...
 *     }
 * }
 * ```
 */
public interface DidMethod<T : CreateDidOptions> {
  /**
   * The name of the did method e.g. 'key', 'jwk', 'ion' etc.
   */
  public val method: String

  /**
   * Creates a new DID and associates it with the provided [keyManager] and optional [options].
   *
   * @param keyManager [KeyManager] instance to manage cryptographic keys related to the new DID.
   * @param options Optional instance of [T], representing method-specific options during the DID creation.
   * @return An instance of [Did] representing the created DID.
   */
  public suspend fun create(keyManager: KeyManager, options: T? = null): Pair<Did, CreationMetadata>

  /**
   * Resolves a DID URL into a set of concrete data and metadata, wrapped in a [DidResolutionResult].
   *
   * @param didUrl A string representing the DID URL that needs to be resolved.
   * @return An instance of [DidResolutionResult] containing resolved data and possibly related metadata.
   */
  public suspend fun resolve(didUrl: String): DidResolutionResult
}
