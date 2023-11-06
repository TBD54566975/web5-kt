# Credential SDK

This SDK enables the creation, signing, verification, and general processing of `Verifiable Credentials` (VCs). It also allows for creation of `Status List Credentials` and has full `Presentation Exchange` support.

## Verifiable Credential

### Features

- Create Verifiable Credentials with flexible data types.
- Sign credentials using decentralized identifiers (DIDs).
- Verify the integrity and authenticity of VCs encoded as JSON Web Tokens (JWTs).
- Parse JWT and JSON representations of VCs into `VerifiableCredential` instances.

### Usage:
### Creating a Verifiable Credential

Create a new `VerifiableCredential` with the following parameters:

- `type`: Type of the credential.
- `issuer`: Issuer URI.
- `subject`: Subject URI.
- `data`: Credential data.

```kotlin
data class StreetCredibility(val localRespect: String, val legit: Boolean)

val vc = VerifiableCredential.create(
  type = "StreetCred",
  issuer = "did:example:issuer",
  subject = "did:example:subject",
  data = StreetCredibility(localRespect = "high", legit = true)
)
```

### Signing a Verifiable Credential
Sign a `VerifiableCredential` with a DID:

- `did`: The DID used to sign the credential.
- `assertionMethodId`: Optional identifier for the assertion method used for signature verification.

```kotlin
val vcJwt = vc.sign(myDid)
```

### Verifying a Verifiable Credential
Verify the integrity and authenticity of a VC JWT:

- `vcJwt`: The VC in JWT format as a String.
```kotlin
try {
    VerifiableCredential.verify(signedVcJwt)
    println("VC Verification successful!")
} catch (e: SignatureException) {
    println("VC Verification failed: ${e.message}")
}
```

### Parsing a JWT into a Verifiable Credential
Parse a JWT into a `VerifiableCredential` instance:

`vcJwt`: The VC JWT as a String.

```kotlin
val vc = VerifiableCredential.parseJwt(vcJwt)
```

### Parsing a JSON into a Verifiable Credential
Parse a JSON string into a `VerifiableCredential` instance:

- `vcJson`: The VC JSON as a String.

```kotlin
val vc = VerifiableCredential.fromJson(vcJsonString)
```


## Status List Credentials

`StatusListCredentials` allows for the creation of status list credentials, such as revocation lists, and the validation of credentials against such lists.

### Features

- Create status list credentials with a simple API, allowing the declaration of revocation or suspension status for a list of credentials.
- Validate individual credentials against a status list to check for revocation or suspension.

### Usage

### Creating a Status List Credential

Creates a new status list credential (e.g., for revocation), use the `create` method:

- `statusListCredentialId`: The id used for the resolvable path to the status list credential.
- `issuer`: The issuer URI of the status list credential.
- `statusPurpose`: The status purpose of the status list cred, eg: revocation,
- `issuedCredentials`: The credentials to be included in the status list credential, eg: revoked credentials.

```kotlin
val statusListCredential = StatusListCredential.create(
    "http://example.com/statuslistcred/id123",
    "did:example:issuer",
    StatusPurpose.REVOCATION,
    listOf(vc1, vc2)
)
```

### Validating a `Verifiable Credential` Against a `Credential Status List`
To validate whether a credential is part of a status list, you can use the validateCredentialInStatusList method:

```kotlin
val isRevoked = StatusListCredential.validateCredentialInStatusList(vc1, statusListCredential)
```

Alternatively, to validate a credential against a status list by fetching the status list credential from a URL:

```kotlin
val isRevoked = StatusListCredential.validateCredentialInStatusList(vc1)
```

## Presentation Exchange

`PresentationExchange` is designed to facilitate the creation of a Verifiable Presentation by providing tools to select and validate Verifiable Credentials against defined criteria.

### Features

- Select credentials that satisfy a given presentation definition.
- Validate if a Verifiable Credential JWT satisfies a Presentation Definition.
- Validate input descriptors within Verifiable Credentials.


### Usage

### Selecting Credentials
Select Verifiable Credentials that meet the criteria of a given presentation definition.

```kotlin
val selectedCredentials = PresentationExchange.selectCredentials(
    credentialsList,
    presentationDefinition
)
```

### Satisfying a Presentation Definition
Validate if a Verifiable Credential JWT satisfies the given presentation definition.

```kotlin 
PresentationExchange.satisfiesPresentationDefinition(vcJwt, presentationDefinition)
```