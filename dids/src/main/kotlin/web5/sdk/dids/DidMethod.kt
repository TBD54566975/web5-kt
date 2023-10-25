package web5.sdk.dids

import web5.sdk.crypto.KeyManager

/**
 * A base abstraction for Decentralized Identifiers (DID) compliant with the W3C DID standard.
 *
 * This abstract class serves as a foundational structure upon which specific DID methods
 * can be implemented. Subclasses should furnish particular method and data models adherent
 * to various DID methods.
 *
 * @property uri The Uniform Resource Identifier (URI) string of the DID.
 * @property keyManager An [KeyManager] instance managing the cryptographic keys linked to the DID.
 *
 * ### Example Implementation
 * Implementing subclasses should provide concrete method and data models specific to a DID method:
 * ```
 * class SpecificDid(uri: String, keyManager: KeyManager): Did(uri, keyManager) {
 *     // Implementation-specific details here.
 * }
 * ```
 *
 * ### Additional Notes
 * Implementers should adhere to the respective DID method specifications ensuring both compliance
 * and interoperability across different DID networks.
 */
public abstract class Did(public val uri: String, public val keyManager: KeyManager) {
  public companion object {
    // static helper methods here
  }
}

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
 * class CreateDidKeyOptions : CreateDidOptions {
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
 * Represents options during the resolution of a Decentralized Identifier (DID).
 *
 * Implementations of this interface may contain properties and methods that provide
 * specific options or metadata during the DID resolution processes following specific
 * DID method specifications.
 *
 * ### Usage Example:
 * Implement this interface in classes where specific creation options are needed
 * for different DID methods.
 *
 * ```
 * class ResolveDidKeyOptions : ResolveDidOptions {
 *     // Implementation-specific options for DID creation.
 * }
 * ```
 */
public interface ResolveDidOptions

/**
 * An interface defining operations for DID methods in accordance with the W3C DID standard.
 *
 * A DID method is a specific set of rules for creating, updating, and revoking DIDs,
 * specified in a DID method specification. Different DID methods utilize different
 * consensus mechanisms, cryptographic algorithms, and registries (or none at all).
 * The purpose of `DidMethod` implementations is to provide logic tailored to a
 * particular method while adhering to the broader operations outlined in the W3C DID standard.
 *
 * Implementations of this interface should provide method-specific logic for
 * creating and resolving DIDs under a particular method.
 *
 * @param T The type of DID that this method can create and resolve, extending [Did].
 *
 * ### Example of a Custom DID Method Implementation:
 * ```
 * class ExampleDidMethod : DidMethod<ExampleDid, ExampleCreateDidOptions> {
 *     override val methodName: String = "example"
 *
 *     override fun create(keyManager: KeyManager, options: ExampleCreateDidOptions?): ExampleDid {
 *         // Implementation-specific logic for creating DIDs.
 *     }
 *
 *     override fun resolve(didUrl: String, opts: ResolveDidOpts?): DidResolutionResult {
 *         // Implementation-specific logic for resolving DIDs.
 *     }
 * }
 * ```
 *
 * ### Notes:
 * - Ensure conformance with the relevant DID method specification for accurate and
 *   interoperable functionality.
 * - Ensure that cryptographic operations utilize secure and tested libraries, ensuring
 *   the reliability and security of DIDs managed by this method.
 */
public abstract class DidMethod<T : Did, O : CreateDidOptions>(public val keyManager: KeyManager) {
  /**
   * A string that specifies the name of the DID method.
   *
   * For instance, in the DID `did:example:123456`, "example" would be the method name.
   */
  public abstract val methodName: String

  /**
   * Creates a new DID.
   *
   * This function should generate a new DID according to the rules of the specific
   * method being implemented, using the provided [KeyManager] and optionally considering
   * any provided [CreateDidOptions].
   *
   * @param options Optionally, an instance of [CreateDidOptions] providing additional options
   *                or requirements for DID creation.
   * @return A new instance of type [T], representing the created DID.
   */
  public abstract fun create(options: O? = null): T

  /**
   * Resolves a DID to its associated DID Document.
   *
   * This function should retrieve and return the DID Document associated with the provided
   * DID URI, in accordance with the rules and mechanisms of the specific DID method being
   * implemented, and optionally considering any provided [ResolveDidOptions].
   *
   * @param did A string containing the DID URI to be resolved.
   * @param options Optionally, an instance of [ResolveDidOptions] providing additional options
   *             or requirements for DID resolution.
   * @return An instance of [DidResolutionResult] containing the resolved DID Document and
   *         any associated metadata.
   */
  public abstract fun resolve(did: String, options: ResolveDidOptions? = null): DidResolutionResult
}
