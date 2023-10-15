package web5.sdk.credentials

/**
 * A utility object for performing operations related to presentation exchanges.
 */
public object PresentationExchange {
  /**
   * Selects credentials from the given list that satisfy the provided presentation definition.
   *
   * @param credentials A list of verifiable credentials.
   * @param presentationDefinition The Presentation Definition to be satisfied.
   * @return A list of verifiable credentials that meet the presentation definition criteria.
   */
  public fun selectCredentials(
    credentials: List<VerifiableCredential>,
    presentationDefinition: PresentationDefinitionV2
  ): List<VerifiableCredential> {
    throw UnsupportedOperationException("pex is untested")
//    return credentials.filter { satisfiesPresentationDefinition(it, presentationDefinition) }
  }

  /**
   * Checks if the given [presentationDefinition] is satisfied based on the provided input descriptors and constraints.
   *
   * @param presentationDefinition The Presentation Definition to be evaluated.
   * @return `true` if the Presentation Definition is satisfied, `false` otherwise.
   * @throws UnsupportedOperationException if certain features like Submission Requirements or Field Filters are not implemented.
   */
  public fun satisfiesPresentationDefinition(
    credential: VerifiableCredential,
    presentationDefinition: PresentationDefinitionV2
  ): Boolean {
    if (!presentationDefinition.submissionRequirements.isNullOrEmpty()) {
      throw UnsupportedOperationException(
        "Presentation Definition's Submission Requirements feature is not implemented"
      )
    }

    return presentationDefinition.inputDescriptors
      .filter { !it.constraints.fields.isNullOrEmpty() }
      .all { inputDescriptorWithFields ->
        val requiredFields = inputDescriptorWithFields.constraints.fields!!.filter { it.optional != true }

        var satisfied = true
        for (field in requiredFields) {
          // we ignore field filters
          if (field.filter != null) {
            throw UnsupportedOperationException("Field Filter is not implemented")
          }

          if (field.path.any { path -> credential.getFieldByJsonPath(path) == null }) {
            satisfied = false
            break
          }
        }
        return satisfied
      }
  }
}
