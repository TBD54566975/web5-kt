# credentials

### VerifiableCredential Creation and Verification

The `VerifiableCredential` class provides methods for the creation, handling, and signing of Verifiable Credentials (
VCs) in JWT format.

- **VerifiableCredential.create**: Creates a Verifiable Credential (VC) in JWT format.
- **VerifiableCredential.validatePayload**: Validates the structure and integrity of a Verifiable Credential payload.
- **VerifiableCredential.verify**: Verifies the integrity of a VC JWT.
- **VerifiableCredential.decode**: Decodes a VC JWT into its constituent parts: header, payload, and signature.

### VP Creation and Verification

The `VerifiablePresentation` class provides utility methods for creation and handling Verifiable Presentations (VPs) in
JWT format.

- **VerifiablePresentation.create**: Creates a Verifiable Presentation (VP) in JWT format from a presentation definition
  and set of credentials.
- **VerifiablePresentation.verify**: Verifies the integrity of a VP JWT.
- **VerifiablePresentation.validatePayload**: Validates the structure and integrity of a Verifiable Presentation
  payload.
- **VerifiablePresentation.decode**: Decodes a VP JWT into its constituent parts: header, payload, and signature.
