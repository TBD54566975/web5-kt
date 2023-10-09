package web5.sdk.dids

import foundation.identity.did.DID

/**
 * Type alias for a DID resolver function.
 * A DID resolver takes a DID URL as input and returns a [DidResolutionResult].
 */
public typealias DidResolver = (String) -> DidResolutionResult

/**
 * Singleton object representing a collection of DID resolvers.
 */
public object DidResolvers {

  // A mutable map to store method-specific DID resolvers.
  private val methodResolvers = mutableMapOf<String, DidResolver>()

  /**
   * Resolves a DID URL using an appropriate resolver based on the DID method.
   *
   * @param didUrl The DID URL to resolve.
   * @return A [DidResolutionResult] containing the resolved DID document or an error message.
   * @throws IllegalArgumentException if resolving the specified DID method is not supported.
   */
  public fun resolve(didUrl: String): DidResolutionResult {
    val parsedDid = DID.fromString(didUrl)
    val resolver = methodResolvers.getOrElse(parsedDid.methodName) {
      throw IllegalArgumentException("Resolving did:${parsedDid.methodName} not supported")
    }

    return resolver(didUrl)
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
