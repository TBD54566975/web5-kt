# Module dids

# Package web5.sdk.dids.methods.key

# Examples

## Creation

### Creating a DID Key

```kt
package example

import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.key.DidKey

val keyManager = InMemoryKeyManager()
val did = DidKey.create(keyManager)
```

### Creating a DID Jwk

```kt
package example

import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.jwk.DidJwk

val keyManager = InMemoryKeyManager()
val did = DidJwk.create(keyManager)
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

  val did = DidKey(uri = didUri, keyManager = keyManager)
}
```

json serializing or deserializing an exported keyset is _not_ limited to Jackson. It can be done using any json library.