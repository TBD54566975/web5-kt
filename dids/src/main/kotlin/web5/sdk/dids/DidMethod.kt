package web5.sdk.dids

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
