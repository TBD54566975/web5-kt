package web5.sdk.dids

import web5.sdk.dids.didcore.Did
import web5.sdk.dids.extensions.supportedMethods

/**
 * Type alias for a DID resolver function.
 * A DID resolver takes a DID URL as input and returns a [DidResolutionResult].
 *
 * @param didUrl The DID URL to resolve.
 * @param options (Optional) Options for resolving the DID.
 * @return A [DidResolutionResult] containing the resolved DID document or an error message.
 */
public typealias DidResolver = (String, ResolveDidOptions?) -> DidResolutionResult

/**
 * Singleton object representing a collection of DID resolvers.
 */
public object DidResolvers {

  // A mutable map to store method-specific DID resolvers.
  private val methodResolvers = supportedMethods.entries.associate {
    it.key to it.value::resolve as DidResolver
  }.toMutableMap()

  /**
   * Resolves a DID URL using an appropriate resolver based on the DID method.
   *
   * @param didUrl The DID URL to resolve.
   * @param options (Optional) Options for resolving the DID.
   * @return A [DidResolutionResult] containing the resolved DID document or an error message.
   * @throws IllegalArgumentException if resolving the specified DID method is not supported.
   */
  public fun resolve(didUrl: String, options: ResolveDidOptions? = null): DidResolutionResult {
    val did = Did.parse(didUrl)
    val resolver = methodResolvers.getOrElse(did.method) {
      throw IllegalArgumentException("Resolving did:${did.method} not supported")
    }

    return resolver(didUrl, options)
  }

  /**
   * Adds a custom resolver for a specific DID method.
   *
   * @param methodName The name of the DID method for which the resolver is being added.
   * @param resolver The resolver function for the specified DID method.
   */
  public fun addResolver(methodName: String, resolver: DidResolver) {
    methodResolvers[methodName] = resolver
  }
}
