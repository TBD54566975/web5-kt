# web5 cookbook

This is the cookbook for a quick reference on how to effectively use this SDK.
Since this is a living document, there's a chance that some examples might be outdated. 
If you find yourself scratching your head because something doesn't work, the best place
to look at is at the test. We strive to maintain a high test coverage, which should give 
you plenty of examples on how to use this SDK.

## DIDs

### Create an ION did

This is the simplest way to create an ion did.

```kotlin
val did = DidIonApi.create(InMemoryKeyManager())
```

The private keys will be stored in the `InMemoryKeyManager`. All the defaults are used for 
the `DidIonApi`, including the endpoint for the ION node used for creation, and uses
`CIO` as the `HttpClientEngine` (see [ktor engines](https://ktor.io/docs/http-client-engines.html)).

### Create an ION did with custom ION endpoint and engine

```kotlin
val keyManager = InMemoryKeyManager()
val ionApi = DidIonApi {
  ionHost = "my_custom_ion_host"
  engine = CIO.create {
    maxConnectionsCount = 10
    requestTimeout = 5.toDuration(DurationUnit.SECONDS).inWholeMilliseconds
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
      relationships = listOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.ASSERTION_METHOD)
    ),
    VerificationMethodCreationParams(
      JWSAlgorithm.ES256K,
      relationships = listOf(PublicKeyPurpose.ASSERTION_METHOD)
    ),
  )
val did = DidIonApi.create(keyManager, opts)
```

### Resolve an ION did

```kotlin
val ionApi = DidIonApi
val didResolutionResult = ionApi.resolve("did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w")
```

### Recover an ION did

Any sidetree based DID, including ION, supports a [recover operation](https://identity.foundation/sidetree/spec/#recover).
This type of operation is useful when the update keys of your DID have been compromised. 

```kotlin
// We create the DID first. 
val ionApi = DidIonApi
val keyManager = InMemoryKeyManager()
val did = ionApi.create(keyManager)
val recoveryKeyAlias = did.creationMetadata!!.keyAliases.verificationKeyAlias

// Imagine that your update key was compromised, so you need to recover your DID.
val opts = RecoverDidIonOptions(
  recoveryKeyAlias = recoveryKeyAlias.first(),
)
val recoverResult = ionApi.recover(keyManager, did.uri, opts)
```

> [!NOTE]
> The `keyManager` MUST contain the recovery private key.

### Deactivate an ION did

```kotlin
// We create the DID first. 
val ionApi = DidIonApi
val keyManager = InMemoryKeyManager()
val did = ionApi.create(keyManager)
val recoveryKeyAlias = did.creationMetadata!!.keyAliases.verificationKeyAlias.first()

// You want to permanently disable the DID, rendering it useless.
val opts = DeactivateDidIonOptions(
  recoveryKeyAlias = recoveryKeyAlias,
)
val deactivateResult = ionApi.deactivate(keyManager, did.uri, opts)
```

> [!NOTE]
> The `keyManager` MUST contain the recovery private key.