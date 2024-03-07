package web5.sdk.dids.extensions

import web5.sdk.crypto.KeyManager
import web5.sdk.dids.ChangemeDid
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.jwk.DidJwk
import web5.sdk.dids.methods.key.DidKey
import web5.sdk.dids.methods.web.DidWeb

internal val supportedMethods = mapOf(
  DidKey.methodName to DidKey.Companion,
  DidJwk.methodName to DidJwk.Companion,
  DidDht.methodName to DidDht.Default,
  DidWeb.methodName to DidWeb.Default
)

/**
 * Creates the appropriate instance for [didUri]. This function validates that all the key material needed for
 * signing and managing the passed in [didUri] exists within the provided [keyManager]. This function is meant
 * to be used when the method of the DID is unknown.
 */
public fun ChangemeDid.Companion.load(didUri: String, keyManager: KeyManager): ChangemeDid {
  return supportedMethods.getValue(Did.parse(didUri).method).load(didUri, keyManager)
}