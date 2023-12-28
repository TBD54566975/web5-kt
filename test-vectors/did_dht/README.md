# `did_dht` Test Vectors

This directory contains test vectors for the `dids` module. It's important to note that the test vectors ensure
that
the implementations are following the [DID DHT specification](https://did-dht.com/).

## `create`

Create test vectors are available in the [json file](./create.json), which contains success and failure test cases.

### Input

The value of `input` is an object with the following properties.

| Property                        | Description                                                                                                                                                                                                                                                                                                             |
|---------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `identityPublicJwk`             | The DID URI to be resolved.                                                                                                                                                                                                                                                                                             |
| `services`                      | An array of arbitrary JSON objects.                                                                                                                                                                                                                                                                                     |
| `additionalVerificationMethods` | An array of _verification method input_ objects. A verification method input is an object that contains two properties:<ul><li>`jwk`: A JWK that will be added as a verification method.</li><li>`purposes`: An array that contains the different verification relationships that the `jwk` will be used for.</li></ul> |

### Output

The value of `output` is a [DID Document](https://www.w3.org/TR/did-core/#dfn-did-documents). For failure cases, the
`errors` property is set to `true`, signalling that an exception or an error should be returned or thrown.

### Reference implementations

The reference implementation for `create` can be found [here]().

## `resolve`

Resolve test vectors are available in the [json file](./resolve.json), which contains success and failure test cases.

### Input

The value of `input` is an object with the following properties:

| Property | Description                 |
|----------|-----------------------------|
| `didUri` | The DID URI to be resolved. |

### Output

The value of `output` is an object that contains the following properties

| Property                | Description                                                                                                                                                                                |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `didDocument`           | the expected [didDocument](https://www.w3.org/TR/did-core/#dfn-diddocument) when `input` is resolved. Note that `didDocument` is set to `null` if resolution is unsuccessful               |
| `didDocumentMetadata`   | the expected [didDocumentMetadata](https://www.w3.org/TR/did-core/#dfn-diddocumentmetadata) when `input` is resolved. Note for `did:dht` this is _always_ an empty object                  |
| `didResolutionMetadata` | the expected [didResolutionMetadata](https://www.w3.org/TR/did-core/#dfn-didresolutionmetadata) when `input` is resolved. Note for `did:dht`, on success, this is _always_ an empty object |

### Reference implementations

The reference implementation for `resolve` can be
found [here](https://github.com/TBD54566975/web5-kt/blob/466e8d8ca9771ae3a98767e5a4a79ac7b1e7a5d8/credentials/src/test/kotlin/web5/sdk/credentials/VerifiableCredentialTest.kt#L261).
