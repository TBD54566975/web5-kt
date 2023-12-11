# `credentials` Test Vectors

## `create`

Create test vectors are available for [success](./create_success.json) and [failure](./create_failure.json) test cases.

### Input

The value of `input` is an object with the following properties.

| Property           | Description                                                                                                              |
|--------------------|--------------------------------------------------------------------------------------------------------------------------|
| `signerDidUri`     | the did uri that will be used to sign the verifiable credential created.                                                 |
| `signerPrivateJwk` | Json Web Key object associated with the `signerDidUri` which will be used for signing `credential`.                      |
| `credential`       | A JSON object that represents a Verifiable Credential 1.1 according to the [spec](https://www.w3.org/TR/vc-data-model/). |

### Output

The value of `output` is a Verifiable Credential 1.1 encoded as a JSON Web Token (
see [here](https://www.w3.org/TR/vc-data-model/#json-web-token) for more details). The signature is created using
the `signerPrivateJwk` private key.

## `verify`

Verify test vectors are available for [success](./verify_success.json) and [failure](./verify_failure.json) test cases.

### Input

The value of `input` is an object with the single property `vcJwt`. The value of `vcJwt` is a Verifiable Credential 1.1
encoded as a JSON Web Token (see [here](https://www.w3.org/TR/vc-data-model/#json-web-token) for more details).

### Output

Output is empty, signalling that no exception nor errors should be thrown for success cases. For failure cases, the
`errors` property is set to `true`, signalling that an exception or an error should be returned or thrown.

