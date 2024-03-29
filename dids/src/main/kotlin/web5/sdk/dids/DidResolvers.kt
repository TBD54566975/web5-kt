package web5.sdk.dids

import web5.sdk.dids.didcore.Did
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.jwk.DidJwk
import web5.sdk.dids.methods.key.DidKey
import web5.sdk.dids.methods.web.DidWeb

/**
 * Type alias for a DID resolver function.
 * A DID resolver takes a DID URL as input and returns a [DidResolutionResult].
 *
 * @param didUrl The DID URL to resolve.
 * @return A [DidResolutionResult] containing the resolved DID document or an error message.
 */
public typealias DidResolver = (String) -> DidResolutionResult

/**
 * Singleton object representing a collection of DID resolvers.
 */
public object DidResolvers {

  private val methodResolvers = mutableMapOf<String, DidResolver>(
    DidKey.methodName to DidKey.Companion::resolve,
    DidJwk.methodName to DidJwk::resolve,
    DidDht.methodName to DidDht.Default::resolve,
    DidWeb.methodName to DidWeb.Default::resolve
  )

  /**
   * Resolves a DID URL using an appropriate resolver based on the DID method.
   *
   * @param didUrl The DID URL to resolve.
   * @return A [DidResolutionResult] containing the resolved DID document or an error message.
   * @throws IllegalArgumentException if resolving the specified DID method is not supported.
   */
  public fun resolve(didUrl: String): DidResolutionResult {
    val did = Did.parse(didUrl)
    val resolver = this.methodResolvers.getOrElse(did.method) {
      throw IllegalArgumentException("Resolving did:${did.method} not supported")
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
    this.methodResolvers[methodName] = resolver
  }
}
