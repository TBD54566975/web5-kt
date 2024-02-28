# Module dids

This module contains the code for generating and resolving DIDs of different major methods.

The documentations of each package contains examples on how to use the SDK. It's meant as a quick reference on how to
effectively use this SDK.

Since documentation is always a living document, there's a chance that some examples might be outdated.
If you find yourself scratching your head because something doesn't work, the best place
to look at is the test files. We strive to maintain a high test coverage, which should give
you plenty of examples on how to use this SDK.

# Package web5.sdk.dids.methods.dht

Package that contains the `DidDht` class, which is used to create and resolve dids using the `dht` method.

# Examples

## Creation

### Creating a DID DHT

```kt
package example

import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.dht.DidDht
import web5.sdk.dids.methods.dht.CreateDidDhtOptions
import foundation.identity.did.Service

val keyManager = InMemoryKeyManager()

// Add a service to the DID Document
val service = Service.Builder()
  .id(URI("test-service"))
  .type("HubService")
  .serviceEndpoint("https://example.com/service)")
  .build()

val opts = CreateDidDhtOptions(
  services = listOf(service),
  // Automatically publishes to the DHT
  publish = true
)

val did = DidDht.create(keyManager, opts)
```

## Resolution

### Resolve a DID DHT

```kotlin
val did = DidDht.resolve("did:dht:gb46emk73wkenrut43ii67a3o5qctojcaucebth7r83pst6yeh8o")
```

# Package web5.sdk.dids.methods.ion

Package that contains the `DidIon` class, which is used to create and resolve dids using the `ion` method.

# Examples

## Creation

### Create an ION did

This is the simplest way to create an ion did.

```kotlin
val did = DidIon.create(InMemoryKeyManager())
```

The private keys will be stored in the `InMemoryKeyManager`. All the defaults are used for
the `DidIonApi`, including the endpoint for the ION node used for creation, and uses
`OkHttp` as the `HttpClientEngine` (see [ktor engines](https://ktor.io/docs/http-client-engines.html)).

### Create an ION did with custom ION endpoint and engine

```kotlin
val keyManager = InMemoryKeyManager()
val ionApi = DidIonApi {
  ionHost = "my_custom_ion_host"
  engine = OkHttp.create {
    preconfigured = OkHttpClient.Builder()
      .connectTimeout(Duration.ofSeconds(4))
      .build()
  }
}
val did = ionApi.create(keyManager)
```

### Create an ION did with custom creation options

This is considered an advanced use case.

Make sure that you have access to the private keys associated with the public keys you're passing in
(i.e. `verification`, `update`, and `recovery` keys). You can generate with the `keyManager`, or
store them elsewhere however you see fit.

```kotlin
val keyManager = InMemoryKeyManager()
val opts = CreateDidIonOptions(
  verificationMethodsToAdd = listOf(
    VerificationMethodCreationParams(
      JWSAlgorithm.ES256K,
      relationships = listOf(Purpose.Authentication, Purpose.AssertionMethod)
    ),
    VerificationMethodCreationParams(
      JWSAlgorithm.ES256K,
      relationships = listOf(Purpose.Authentication)
    ),
  )
)
  val did = DidIon.create(keyManager, opts)
```

## Resolution

### Resolve an ION did

```kotlin
val didResolutionResult = DidIon.resolve("did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w")
```

## DID ION Operations

### Recover an ION did

Any sidetree based DID, including ION, supports
a [recover operation](https://identity.foundation/sidetree/spec/#recover).
This type of operation is useful when the update keys of your DID have been compromised.

```kotlin
// We create the DID first. 
val keyManager = InMemoryKeyManager()
val did = DidIon.create(keyManager)
val recoveryKeyAlias = did.creationMetadata!!.keyAliases.verificationKeyAlias

// Imagine that your update key was compromised, so you need to recover your DID.
val opts = RecoverDidIonOptions(
  recoveryKeyAlias = recoveryKeyAlias.first(),
)
val recoverResult = DidIon.recover(keyManager, did.uri, opts)
```

**NOTE**: The `keyManager` MUST contain the recovery private key.

### Deactivate an ION did

```kotlin
// We create the DID first. 
val ionApi = DidIon
val keyManager = InMemoryKeyManager()
val did = ionApi.create(keyManager)
val recoveryKeyAlias = did.creationMetadata!!.keyAliases.verificationKeyAlias.first()

// You want to permanently disable the DID, rendering it useless.
val opts = DeactivateDidIonOptions(
  recoveryKeyAlias = recoveryKeyAlias,
)
val deactivateResult = ionApi.deactivate(keyManager, did.uri, opts)
```

**NOTE**: The `keyManager` MUST contain the recovery private key.

# Package web5.sdk.dids.methods.key

Package that contains the `DidKey` class, which is used to create and resolve dids using the `key` method.

## Examples

### Create a DID Key

```kt
package example

import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.key.DidKey

val keyManager = InMemoryKeyManager()
val did = DidKey.create(keyManager)
```

## Export / Import

If you're using `InMemoryKeyManager` you can export you can export a DID you've created and its associated private key
material

```kt
package example

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.key.DidKey

fun main() {
  val keyManager = InMemoryKeyManager()
  val did = DidKey.create(keyManager)

  // export did and key material
  println(did.uri)

  val jsonMapper = ObjectMapper()
    .registerKotlinModule()
    .setSerializationInclusion(JsonInclude.Include.NON_NULL)

  val serializedKeySet = jsonMapper.writeValueAsString(keyManager.export())
  println(serializedKeySet)
}
```

Similarly, when using `InMemoryKeyManager` you can import a pre-existing DID and its associated key material like so:

```kt
package example

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.key.DidKey

fun main() {
  val jsonMapper = ObjectMapper()
    .registerKotlinModule()
    .setSerializationInclusion(JsonInclude.Include.NON_NULL)

  val didUri = "did:key:zQ3shjXPdC6uPLTGFPTyJce25EaboYQSdTCYx1xuazHQHjSFF"
  val serializedKeySet =
    """[{"kty":"EC","d":"X6A_7ZYpF_2OB6R1FMawKg2yG0-i92IGM312AuS8pK4","use":"sig","crv":"secp256k1","kid":"BEfysC8d0HFZpkXEQlswUHHDAg8gQPT9y2fvDpijfH4","x":"SJIF0v1D3-OPHVP3jaKu4t3e7n5hj1sr4KINCi41qC4","y":"wHKcRjfxcuz5M3DBc6LqNANDuz-kMrIRZsiUPfRd-B8","alg":"ES256K"}]"""

  val jsonKeySet: List<Map<String, Any>> = jsonMapper.readValue(serializedKeySet)

  val keyManager = InMemoryKeyManager()
  keyManager.import(jsonKeySet)

  val did = DidKey.load(did = didUri, keyManager = keyManager)
}
```

json serializing or deserializing an exported keyset is _not_ limited to Jackson. It can be done using any json library.

# Package web5.sdk.dids.methods.web

Package that contains the `DidWeb` class, which is used to create and resolve dids using the `web` method.

## Examples

### Resolve a Web did

```kotlin
val didResolutionResult = DidWeb.resolve("did:web:users.tbddev.org:demo")
```

# Package web5.sdk.dids.methods.jwk

Package that contains the `DidJwk` class, which is used to create and resolve dids using the `jwk` method.

## Examples

### Creating a DID Jwk

```kt
package example

import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.jwk.DidJwk

val keyManager = InMemoryKeyManager()
val did = DidJwk.create(keyManager)
```