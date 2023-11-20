package web5.sdk.dids

import foundation.identity.did.DID
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.ion.DidIon
import web5.sdk.dids.methods.jwk.DidJwk
import web5.sdk.dids.methods.key.DidKey

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
  private val methodResolvers = mutableMapOf<String, DidResolver>(
    DidKey.methodName to DidKey.Companion::resolve,
    DidJwk.methodName to DidJwk.Companion::resolve,
    DidIon.methodName to DidIon.Default::resolve,
    DidDht.methodName to DidDht.Default::resolve,
    DidWeb.methodName to DidWeb.Default::resolve
  )

  /**
   * Resolves a DID URL using an appropriate resolver based on the DID method.
   *
   * @param didUrl The DID URL to resolve.
   * @param options (Optional) Options for resolving the DID.
   * @return A [DidResolutionResult] containing the resolved DID document or an error message.
   * @throws IllegalArgumentException if resolving the specified DID method is not supported.
   */
  public fun resolve(didUrl: String, options: ResolveDidOptions? = null): DidResolutionResult {
    val parsedDid = DID.fromString(didUrl)
    val resolver = methodResolvers.getOrElse(parsedDid.methodName) {
      throw IllegalArgumentException("Resolving did:${parsedDid.methodName} not supported")
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
