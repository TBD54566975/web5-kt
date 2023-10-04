package web5.credentials

import web5.credentials.model.VerifiableCredentialType
import java.util.Date

/**
 * Utility class for validating verifiable credentials (VCs).
 */
public object Validation {

  /**
   * Exception class for validation errors.
   *
   * @param message A descriptive error message.
   */
  public class ValidationError(message: String) : Exception(message)

  private fun validateDate(date: Date): Boolean {
    return date.time > 0
  }

  /**
   * Validates the properties and structure of a verifiable credential (VC).
   *
   * @param verifiableCredential The verifiable credential to be validated.
   * @throws ValidationError if the validation fails, indicating issues with the VC's structure or properties.
   */
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
