package web5.sdk.dids

import foundation.identity.did.DID

public typealias DidResolver = (String) -> DidResolutionResult

public object DidResolvers {
  private val methodResolvers = mutableMapOf<String, DidResolver>(
    DidKeyMethod.method to DidKeyMethod::resolve,
  )

  public fun resolve(didUrl: String): DidResolutionResult {
    val parsedDid = DID.fromString(didUrl)
    val resolver = methodResolvers.getOrElse(parsedDid.methodName) {
      throw IllegalArgumentException("resolving did:${parsedDid.methodName} not supported")
    }

    return resolver(didUrl)
  }

  public fun addResolver(methodName: String, resolver: DidResolver) {
    methodResolvers[methodName] = resolver
  }
}