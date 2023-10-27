package web5.sdk.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.networknt.schema.JsonSchema
import com.nfeld.jsonpathkt.JsonPath
import com.nfeld.jsonpathkt.extension.read
import com.nimbusds.jose.Payload
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT

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
   * @throws UnsupportedOperationException if certain features like Submission Requirements are not implemented.
   */
  public fun satisfiesPresentationDefinition(
    vcJwt: String,
    presentationDefinition: PresentationDefinitionV2
  ) {
    val vc = JWTParser.parse(vcJwt) as SignedJWT

    if (!presentationDefinition.submissionRequirements.isNullOrEmpty()) {
      throw UnsupportedOperationException(
        "Presentation Definition's Submission Requirements feature is not implemented"
      )
    }

    presentationDefinition.inputDescriptors
      .filter { !it.constraints.fields.isNullOrEmpty() }
      .forEach { inputDescriptorWithFields ->
        validateInputDescriptorsWithFields(inputDescriptorWithFields, vc.payload)
      }
  }

  private fun validateInputDescriptorsWithFields(
    inputDescriptorWithFields: InputDescriptorV2,
    vcPayload: Payload
  ) {
    val requiredFields = inputDescriptorWithFields.constraints.fields!!.filter { it.optional != true }

    requiredFields.forEach { field ->
      val matchedPath = field.path.find { path -> vcPayload.toJSONObject()[path] != null }
        ?: throw PresentationExchangeError("Could not find matching field for required field: $field.id")

      when {
        field.filterSchema != null -> {
          val fieldValue = JsonPath.parse(vcPayload.toString())?.read<JsonNode>(matchedPath)
            ?: throw PresentationExchangeError("Failed to read VC field $matchedPath as JsonNode")
          vcSatisfiesFieldFilterSchema(fieldValue, field.filterSchema!!)
        }

        else -> {
          return
        }
      }
    }
  }

  private fun vcSatisfiesFieldFilterSchema(fieldValue: JsonNode, schema: JsonSchema) {
    val validationMessages = schema.validate(fieldValue)
    require(validationMessages.isEmpty()) {
      PresentationExchangeError(validationMessages.toString())
    }
  }
}

public class PresentationExchangeError(message: String) : Error(message)