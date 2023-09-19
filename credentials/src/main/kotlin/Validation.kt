package web5.credentials

import java.util.Date

public class Validation {

  public companion object {
    public class ValidationError(message: String) : Exception(message)

    private fun validateDate(date: Date): Boolean {
      if (date.time > 0) {
        return true
      } else {
        return false
      }
    }

    public fun validate(verifiableCredential: VerifiableCredentialType) {
      if (verifiableCredential.getJsonObject() == null) {
        throw ValidationError("Bad or missing JSON object.")
      }

      if (verifiableCredential.getContexts().isEmpty()) {
        throw ValidationError("Bad or missing '@context'.")
      }

      if (!VerifiableCredentialType.DEFAULT_JSONLD_CONTEXTS[0].equals(verifiableCredential.getContexts().get(0))) {
        throw ValidationError(
          "First value of @context must be " + VerifiableCredentialType.DEFAULT_JSONLD_CONTEXTS[0] + ": " + verifiableCredential.getContexts().get(
            0
          )
        )
      }

      if (verifiableCredential.getTypes().isEmpty()) {
        throw ValidationError("Bad or missing 'type'.")
      }

      if (!verifiableCredential.getTypes().contains(VerifiableCredentialType.DEFAULT_JSONLD_TYPES[0])) {
        throw ValidationError("'type' must contain 'VerifiableCredential': " + verifiableCredential.getTypes())
      }

      if (verifiableCredential.getIssuer() == null) {
        throw ValidationError("Bad or missing 'issuer'.")
      }

      if (verifiableCredential.getIssuanceDate() == null) {
        throw ValidationError("Missing 'issuanceDate'.")
      }

      if (!validateDate(verifiableCredential.getIssuanceDate())) {
        throw ValidationError("Bad 'issuanceDate'.")
      }

      if (verifiableCredential.getExpirationDate() != null && !validateDate(verifiableCredential.getExpirationDate())) {
        throw ValidationError("Bad 'expirationDate'.")
      }

      if (verifiableCredential.getCredentialSubject() == null) {
        throw ValidationError("Bad or missing 'credentialSubject'.")
      }
    }
  }
}
