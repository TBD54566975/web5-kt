package web5.sdk.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.networknt.schema.JsonSchema
import com.nfeld.jsonpathkt.JsonPath
import com.nfeld.jsonpathkt.extension.read
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
   * Validates a list of Verifiable Credentials (VCs) against a specified Presentation Definition.
   *
   * This function ensures that the provided VCs meet the criteria defined in the Presentation Definition.
   * It first checks for the presence of Submission Requirements in the definition and throws an exception if they exist,
   * as this feature is not implemented. Then, it maps the input descriptors in the presentation definition to the
   * corresponding VCs. If the number of mapped descriptors does not match the required count, an error is thrown.
   *
   * @param vcJwts Iterable of VCs in JWT format to validate.
   * @param presentationDefinition The Presentation Definition V2 object against which VCs are validated.
   * @throws UnsupportedOperationException If Submission Requirements are present in the definition.
   * @throws PresentationExchangeError If the number of input descriptors matched is less than required.
   */
  public fun satisfiesPresentationDefinition(
    vcJwts: Iterable<String>,
    presentationDefinition: PresentationDefinitionV2
  ) {
    if (!presentationDefinition.submissionRequirements.isNullOrEmpty()) {
      throw UnsupportedOperationException(
        "Presentation Definition's Submission Requirements feature is not implemented"
      )
    }

    val inputDescriptorToVcMap = mapInputDescriptorsToVCs(vcJwts, presentationDefinition)

    if (inputDescriptorToVcMap.size != presentationDefinition.inputDescriptors.size) {
      throw PresentationExchangeError(
        "Missing input descriptors: The presentation definition requires " +
          "${presentationDefinition.inputDescriptors.size} descriptors, but only " +
          "${inputDescriptorToVcMap.size} were found. Check and provide the missing descriptors."
      )
    }
  }

  private fun mapInputDescriptorsToVCs(
    vcJwtList: Iterable<String>,
    presentationDefinition: PresentationDefinitionV2
  ): Map<InputDescriptorV2, List<String>> {
    return presentationDefinition.inputDescriptors.associateWith { inputDescriptor ->
      val satisfyingVCs = vcJwtList.filter { vcJwt ->
        vcSatisfiesInputDescriptor(vcJwt, inputDescriptor)
      }
      satisfyingVCs
    }.filterValues { it.isNotEmpty() }
  }

  /**
   * Evaluates if a Verifiable Credential (VC) satisfies the criteria defined in an Input Descriptor.
   *
   * Parses a Verifiable Credential (VC) from JWT format and verifies if it satisfies the Input Descriptor's criteria.
   * This function evaluates each required field (where 'optional' is not true) in the descriptor against the VC's JSON payload.
   * It extracts data from the VC payload using JSON paths defined in each field and checks compliance with any defined schema.
   * Returns false if any required field is missing or fails schema validation, indicating non-compliance with the Input Descriptor.
   * Otherwise, it returns true, signifying that the VC meets all criteria.
   *
   * @param vcJwt The JWT string representing the Verifiable Credential.
   * @param inputDescriptor An instance of InputDescriptorV2 defining the criteria to be satisfied by the VC.
   * @return Boolean indicating whether the VC satisfies the criteria of the Input Descriptor.
   * @throws PresentationExchangeError Any errors during processing
   */
  private fun vcSatisfiesInputDescriptor(
    vcJwt: String,
    inputDescriptor: InputDescriptorV2
  ): Boolean {
    val vc = JWTParser.parse(vcJwt) as SignedJWT

    val vcPayloadJson = JsonPath.parse(vc.payload.toString())
      ?: throw PresentationExchangeError("Failed to parse VC payload as JSON.")

    // If the Input Descriptor has constraints and fields defined, evaluate them.
    inputDescriptor.constraints?.fields?.let { fields ->
      val requiredFields = fields.filter { field -> field.optional != true }

      for (field in requiredFields) {
        val matchedFields = field.path.mapNotNull { path -> vcPayloadJson.read<JsonNode>(path) }
        if (matchedFields.isEmpty()) {
          // If no matching fields are found for a required field, the VC does not satisfy this Input Descriptor.
          return false
        }

        // If there is a filter schema, process it
        if (field.filterSchema != null) {
          val satisfiesSchema = evaluateMatchedFields(matchedFields, field.filterSchema!!)
          if (!satisfiesSchema) {
            // If the field value does not satisfy the schema, the VC does not satisfy this Input Descriptor.
            return false
          }
        }
      }
    }

    // If the VC passes all the checks, it satisfies the criteria of the Input Descriptor.
    return true
  }

  /**
   * Checks if any JsonNode in 'matchedFields' satisfies the 'schema'.
   * Iterates through nodes: if a node or any element in a node array meets the schema, returns true; otherwise false.
   *
   * @param matchedFields List of JsonNodes to validate.
   * @param schema JsonSchema to validate against.
   * @return True if any field satisfies the schema, false if none do.
   */
  private fun evaluateMatchedFields(matchedFields: List<JsonNode>, schema: JsonSchema): Boolean {
    for (fieldValue in matchedFields) {
      if (fieldValue.isArray() && fieldValue.any { valueSatisfiesFieldFilterSchema(it, schema) }) {
        return true
      }

      if (fieldValue.isArray() && schema.isExpectingArray() && valueSatisfiesFieldFilterSchema(fieldValue, schema)) {
        return true
      }

      if (!fieldValue.isArray() && valueSatisfiesFieldFilterSchema(fieldValue, schema)) {
        return true
      }
    }
    return false
  }

  private fun JsonSchema.isExpectingArray(): Boolean {
    val schemaNode: JsonNode = this.schemaNode
    return if (schemaNode is ObjectNode) {
      val typeNode = schemaNode.get("type")
      typeNode != null && typeNode.asText() == "array"
    } else {
      false
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