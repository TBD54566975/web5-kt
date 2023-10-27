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
   * Validates whether a verifiable credential (VC) satisfies a given Presentation Definition.
   *
   * @param vcJwt The VC in JWT format.
   * @param presentationDefinition The Presentation Definition to be satisfied.
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

  /**
   * Validates whether the input descriptors with fields in a Presentation Definition are satisfied by
   * the payload of a verifiable credential (VC).
   *
   * @param inputDescriptorWithFields The input descriptor with fields to be validated.
   * @param vcPayload The payload of the VC.
   */
  private fun validateInputDescriptorsWithFields(
    inputDescriptorWithFields: InputDescriptorV2,
    vcPayload: Payload
  ) {
    val requiredFields = inputDescriptorWithFields.constraints.fields!!.filter { it.optional != true }

    requiredFields.forEach { field ->
      val vcPayloadJson = JsonPath.parse(vcPayload.toString())
        ?: throw PresentationExchangeError("Failed to parse VC $vcPayload as JsonNode")

      val matchedFields = field.path.mapNotNull { path -> vcPayloadJson.read<JsonNode>(path) }
      if (matchedFields.isEmpty()) {
        throw PresentationExchangeError("Could not find matching field for path: ${field.path.joinToString()}")
      }

      when {
        field.filterSchema != null -> matchedFields.any {vcSatisfiesFieldFilterSchema(it, field.filterSchema!!)}
        else -> return
      }
    }
  }

  /**
   * Validates whether a verifiable credential (VC) field value satisfies a JSON schema.
   *
   * @param fieldValue The field value of the VC as a JsonNode.
   * @param schema The JSON schema to validate against.
   */
  private fun vcSatisfiesFieldFilterSchema(fieldValue: JsonNode, schema: JsonSchema): Boolean {
    val validationMessages = schema.validate(fieldValue)
    when {
      validationMessages.isEmpty() -> return true
      else -> throw PresentationExchangeError("validating $fieldValue failed: ${validationMessages.joinToString()}")
    }
  }
}

/**
 * Custom error class for exceptions related to the Presentation Exchange.
 *
 * @param message The error message.
 */
public class PresentationExchangeError(message: String) : Error(message)