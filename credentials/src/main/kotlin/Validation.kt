package web5.credentials

import java.util.*

public class Validation private constructor() {

  public companion object {
    public class ValidationError(message: String) : Exception(message)

    private fun validateDate(date: Date): Boolean {
      return date.time > 0
    }

    public fun validate(verifiableCredential: VerifiableCredentialType) {
      if (verifiableCredential.jsonObject.isNullOrEmpty()) {
        throw ValidationError("Bad or missing JSON object.")
      }

      if (verifiableCredential.contexts.isEmpty()) {
        throw ValidationError("Bad or missing '@context'.")
      }

      if (!VerifiableCredentialType.DEFAULT_JSONLD_CONTEXTS[0].equals(verifiableCredential.contexts[0])) {
        throw ValidationError(
          "First value of @context must be ${VerifiableCredentialType.DEFAULT_JSONLD_CONTEXTS[0]}: " +
            "${verifiableCredential.contexts[0]}"
        )
      }

      if (verifiableCredential.types.isEmpty()) {
        throw ValidationError("Bad or missing 'type'.")
      }

      if (!verifiableCredential.types.contains(VerifiableCredentialType.DEFAULT_JSONLD_TYPES[0])) {
        throw ValidationError("'type' must contain 'VerifiableCredential': " + verifiableCredential.types)
      }

      if (verifiableCredential.issuer == null) {
        throw ValidationError("Bad or missing 'issuer'.")
      }

      if (verifiableCredential.issuanceDate == null) {
        throw ValidationError("Missing 'issuanceDate'.")
      }

      if (!validateDate(verifiableCredential.issuanceDate)) {
        throw ValidationError("Bad 'issuanceDate'.")
      }

      if (verifiableCredential.expirationDate != null && !validateDate(verifiableCredential.expirationDate)) {
        throw ValidationError("Bad 'expirationDate'.")
      }

      if (verifiableCredential.credentialSubject == null) {
        throw ValidationError("Bad or missing 'credentialSubject'.")
      }
    }
  }
}
