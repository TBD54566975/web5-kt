package web5.sdk.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.networknt.schema.JsonSchema
import com.nfeld.jsonpathkt.JsonPath
import com.nfeld.jsonpathkt.extension.read
import com.nimbusds.jose.Payload
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT

/**
 * The `PresentationExchange` object provides functions for working with Verifiable Credentials
 * and Presentation Definitions during a presentation exchange process.
 */
public object PresentationExchange {
  /**
   * Selects credentials that satisfy a given presentation definition.
   *
   * @param credentials The list of Verifiable Credentials to select from.
   * @param presentationDefinition The Presentation Definition to match against.
   * @return A list of Verifiable Credentials that satisfy the Presentation Definition.
   * @throws UnsupportedOperationException If the method is untested and not recommended for use.
   */
  public fun selectCredentials(
    credentials: List<VerifiableCredential>,
    presentationDefinition: PresentationDefinitionV2
  ): List<VerifiableCredential> {
    throw UnsupportedOperationException("pex is untested")
    // Uncomment the following line to filter credentials based on the Presentation Definition
    // return credentials.filter { satisfiesPresentationDefinition(it, presentationDefinition) }
  }

  /**
   * Validates if a Verifiable Credential JWT satisfies a Presentation Definition.
   *
   * @param vcJwt The Verifiable Credential JWT as a string.
   * @param presentationDefinition The Presentation Definition to validate against.
   * @throws UnsupportedOperationException If the Presentation Definition's Submission Requirements
   * feature is not implemented.
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
   * Validates the input descriptors with associated fields in a Verifiable Credential.
   *
   * @param inputDescriptorWithFields The Input Descriptor with associated fields.
   * @param vcPayload The payload of the Verifiable Credential.
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
        field.filterSchema != null -> {
          matchedFields.any { fieldValue ->
            when {
              // When the field is an array, JSON schema is applied to each array item.
              fieldValue.isArray -> {
                if (fieldValue.none { valueSatisfiesFieldFilterSchema(it, field.filterSchema!!) })
                  throw PresentationExchangeError("Validating $fieldValue against ${field.filterSchema} failed")
                true
              }

              // Otherwise, JSON schema is applied to the entire value.
              else -> {
                valueSatisfiesFieldFilterSchema(fieldValue, field.filterSchema!!)
              }
            }
          }
        }

        else -> return
      }
    }
  }

  /**
   * Checks if a field's value satisfies the given JSON schema.
   *
   * @param fieldValue The JSON field value to validate.
   * @param schema The JSON schema to validate against.
   * @return `true` if the value satisfies the schema, `false` otherwise.
   */
  private fun valueSatisfiesFieldFilterSchema(fieldValue: JsonNode, schema: JsonSchema): Boolean {
    val validationMessages = schema.validate(fieldValue)
    return when {
      validationMessages.isEmpty() -> true
      // TODO try and surface the validation messages in error
      else -> false
    }
  }
}

/**
 * Custom error class for exceptions related to the Presentation Exchange.
 *
 * @param message The error message.
 */
public class PresentationExchangeError(message: String) : Error(message)