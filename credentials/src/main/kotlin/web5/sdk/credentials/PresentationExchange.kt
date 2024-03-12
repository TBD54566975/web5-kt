package web5.sdk.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.networknt.schema.JsonSchema
import com.nfeld.jsonpathkt.JsonPath
import com.nfeld.jsonpathkt.extension.read
import web5.sdk.credentials.model.InputDescriptorMapping
import web5.sdk.credentials.model.InputDescriptorV2
import web5.sdk.credentials.model.PresentationDefinitionV2
import web5.sdk.credentials.model.PresentationDefinitionV2Validator
import web5.sdk.credentials.model.PresentationSubmission
import web5.sdk.credentials.model.PresentationSubmissionValidator
import web5.sdk.dids.jwt.Jwt
import java.util.UUID

/**
 * The `PresentationExchange` object provides functions for working with Verifiable Credentials
 * and Presentation Definitions during a presentation exchange process.
 */
public object PresentationExchange {
  /**
   * Selects credentials that satisfy a given presentation definition.
   *
   * @param vcJwts Iterable of VCs in JWT format to select from.
   * @param presentationDefinition The Presentation Definition to match against.
   * @return A list of Verifiable Credentials that satisfy the Presentation Definition.
   */
  @Throws(UnsupportedOperationException::class)
  public fun selectCredentials(
    vcJwts: Iterable<String>,
    presentationDefinition: PresentationDefinitionV2
  ): List<String> {
    val inputDescriptorToVcMap = mapInputDescriptorsToVCs(vcJwts, presentationDefinition)
    return inputDescriptorToVcMap.flatMap { it.value }.toSet().toList()
  }

  /**
   * Validates a list of Verifiable Credentials (VCs) against a specified Presentation Definition.
   *
   * This function ensures that the provided VCs meet the criteria defined in the Presentation Definition.
   * It first checks for the presence of Submission Requirements in the definition and throws an exception if they exist,
   * as this feature is not implemented. Then, it maps the input descriptors in the presentation definition to the
   * corresponding VCs. If the number of mapped descriptors does not match the required count, an exception is thrown.
   *
   * @param vcJwts Iterable of VCs in JWT format to validate.
   * @param presentationDefinition The Presentation Definition V2 object against which VCs are validated.
   * @throws UnsupportedOperationException If Submission Requirements are present in the definition.
   * @throws IllegalArgumentException If the number of input descriptors matched is less than required
   * or if the VC payload cannot be parsed as JSON.
   */
  @Throws(UnsupportedOperationException::class, IllegalArgumentException::class)
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

    require(inputDescriptorToVcMap.size == presentationDefinition.inputDescriptors.size) {
      "Missing input descriptors: The presentation definition requires " +
        "${presentationDefinition.inputDescriptors.size} descriptors, but only " +
        "${inputDescriptorToVcMap.size} were found. Check and provide the missing descriptors."
    }
  }

  /**
   * Creates a Presentation Submission in which the list of Verifiable Credentials JWTs (VCs) fulfills the given Presentation Definition.
   * Presentation Definition.
   *
   *
   * @param vcJwts Iterable of VCs in JWT format to validate.
   * @param presentationDefinition The Presentation Definition V2 object against which VCs are validated.
   * @return A PresentationSubmission object.
   * @throws UnsupportedOperationException if the presentation definition contains submission requirements.
   * @throws IllegalStateException if no VC corresponds to an input descriptor or if a VC's index is not found.
   * @throws PresentationExchangeError If the number of input descriptors matched is less than required.
   */
  public fun createPresentationFromCredentials(
    vcJwts: Iterable<String>,
    presentationDefinition: PresentationDefinitionV2
  ): PresentationSubmission {

    satisfiesPresentationDefinition(vcJwts, presentationDefinition)

    val inputDescriptorToVcMap = mapInputDescriptorsToVCs(vcJwts, presentationDefinition)
    val vcJwtToIndexMap = vcJwts.withIndex().associate { (index, vcJwt) -> vcJwt to index }

    val descriptorMapList = mutableListOf<InputDescriptorMapping>()
    for ((inputDescriptor, vcList) in inputDescriptorToVcMap) {
      // Even if multiple VCs satisfy the input descriptor we use the first
      val vcJwt = vcList.firstOrNull()
      checkNotNull(vcJwt) { "Illegal state: no vc corresponds to input descriptor" }

      val vcIndex = vcJwtToIndexMap[vcJwt]
      checkNotNull(vcIndex) { "Illegal state: vcJwt index not found" }

      descriptorMapList.add(
        InputDescriptorMapping(
          id = inputDescriptor.id,
          path = "$.verifiableCredential[$vcIndex]",
          format = "jwt_vc"
        )
      )
    }

    return PresentationSubmission(
      id = UUID.randomUUID().toString(),
      definitionId = presentationDefinition.id,
      descriptorMap = descriptorMapList
    )
  }

  /**
   * Validates whether an object is usable as a presentation definition or not.
   *
   * Model as specified in https://identity.foundation/presentation-exchange/#presentation-definition.
   *
   * The checks are as follows:
   * 1. Ensures that the presentation definition's ID is not empty.
   * 2. Validates that the name, if present, is not empty.
   * 3. Checks that the purpose, if provided, is not empty.
   * 4. Verifies the uniqueness of all inputDescriptor IDs within the presentation.
   * 5. Ensures that FieldV2 ids are unique across all input descriptors.
   * 6. For each input descriptor, it validates the descriptor using InputDescriptorV2Validator.
   *
   * Throws an [PexValidationException] if the provided object does not conform to the Presentation Definition
   */
  @Throws(PexValidationException::class)
  public fun validateDefinition(presentationDefinition: PresentationDefinitionV2) {
    PresentationDefinitionV2Validator.validate(presentationDefinition)
  }

  /**
   * Validates whether an object is usable as a presentation submission or not.
   *
   * Model as specified in https://identity.foundation/presentation-exchange/#presentation-submission.
   *
   * The checks are as follows:
   * 1. Ensures that the presentation submission's id is not empty.
   * 2. Validates that the definitionId is not empty.
   * 3. Validates descriptorMap is a non-empty list.
   * 4. Check for unique inputDescriptor ids at top level
   * 5. Verifies the input descriptor mapping ids are the same on all levels of nesting.
   * 6. Ensures that the path is valid across all levels of nesting
   *
   * Throws an [PexValidationException] if the provided object does not conform to the Presentation Definition
   */
  @Throws(PexValidationException::class)
  public fun validateSubmission(presentationSubmission: PresentationSubmission) {
    PresentationSubmissionValidator.validate(presentationSubmission)
  }

  private fun mapInputDescriptorsToVCs(
    vcJwtList: Iterable<String>,
    presentationDefinition: PresentationDefinitionV2
  ): Map<InputDescriptorV2, List<String>> {
    val vcJwtListWithNodes = vcJwtList.zip(vcJwtList.map { vcJwt ->
      val vc = Jwt.decode(vcJwt)

      JsonPath.parse(vc.claims.toString())
        ?: throw JsonPathParseException()
    })
    return presentationDefinition.inputDescriptors.associateWith { inputDescriptor ->
      vcJwtListWithNodes.filter { (_, node) ->
        vcSatisfiesInputDescriptor(node, inputDescriptor)
      }.map { (vcJwt, _) -> vcJwt }
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
   * @throws JsonPathParseException If the VC payload cannot be parsed as JSON.
   */
  @Throws(JsonPathParseException::class)
  private fun vcSatisfiesInputDescriptor(
    vcPayloadJson: JsonNode,
    inputDescriptor: InputDescriptorV2
  ): Boolean {
    // If the Input Descriptor has constraints and fields defined, evaluate them.
    inputDescriptor.constraints.fields?.let { fields ->
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