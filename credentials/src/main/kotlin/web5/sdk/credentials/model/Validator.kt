package web5.sdk.credentials.model

import com.fasterxml.jackson.databind.JsonNode
import com.nfeld.jsonpathkt.JsonPath
import com.nfeld.jsonpathkt.extension.read
import web5.sdk.credentials.JsonPathParseException
import web5.sdk.credentials.PexValidationException

/**
 * PresentationDefinitionV2Validator Validator.
 **/
public object PresentationDefinitionV2Validator {

  /**
   * Validates a PresentationDefinitionV2.
   *
   * This method performs several checks to ensure the integrity of the presentation definition model object:
   * 1. Ensures that the presentation definition's ID is not empty.
   * 2. Validates that the name, if present, is not empty.
   * 3. Checks that the purpose, if provided, is not empty.
   * 4. Verifies the uniqueness of all inputDescriptor IDs within the presentation.
   * 5. Ensures that FieldV2 ids are unique across all input descriptors.
   * 6. For each input descriptor, it validates the descriptor using InputDescriptorV2Validator.
   * @throws PexValidationException if the PresentationDefinitionV2 is not valid.
   */
  @Throws(PexValidationException::class)
  public fun validate(presentationDefinition: PresentationDefinitionV2) {
    if (presentationDefinition.id.isEmpty()) {
      throw PexValidationException("PresentationDefinition id must not be empty")
    }

    presentationDefinition.name?.let {
      if (it.isEmpty()) {
        throw PexValidationException("PresentationDefinition name must not be empty")
      }
    }

    presentationDefinition.purpose?.let {
      if (it.isEmpty()) {
        throw PexValidationException("PresentationDefinition purpose must not be empty")
      }
    }

    // Check for unique inputDescriptor IDs
    val ids = presentationDefinition.inputDescriptors.map { it.id }
    if (ids.size != ids.toSet().size) {
      throw PexValidationException("All inputDescriptor ids must be unique")
    }

    // Check for unique FieldV2 ids across all input descriptors
    val fieldIds = presentationDefinition.inputDescriptors.flatMap {
      it.constraints.fields?.mapNotNull { field -> field.id } ?: listOf()
    }
    if (fieldIds.size != fieldIds.toSet().size) {
      throw PexValidationException("Field ids must be unique across all input descriptors")
    }

    presentationDefinition.inputDescriptors.forEach { descriptor ->
      InputDescriptorV2Validator.validate(descriptor)
    }
  }
}

/**
 * InputDescriptorV2Validator Validator.
 **/
public object InputDescriptorV2Validator {

  /**
   * Validates an InputDescriptorV2.
   *
   * This method conducts several checks to ensure the integrity of the input descriptor:
   * 1. Ensures that the input descriptor's ID is not empty.
   * 2. Validates that the name, if present, is not empty.
   * 3. Checks that the purpose, if provided, is not empty.
   * 4. For each field in the input descriptor's constraints, it validates the field using FieldV2Validator.
   * @throws PexValidationException if the InputDescriptorV2 is not valid.
   */
  @Throws(PexValidationException::class)
  public fun validate(inputDescriptor: InputDescriptorV2) {
    if (inputDescriptor.id.isEmpty()) {
      throw PexValidationException("InputDescriptor id must not be empty")
    }

    inputDescriptor.name?.let {
      if (it.isEmpty()) {
        throw PexValidationException("InputDescriptor name must not be empty")
      }
    }

    inputDescriptor.purpose?.let {
      if (it.isEmpty()) {
        throw PexValidationException("InputDescriptor purpose must not be empty")
      }
    }

    inputDescriptor.constraints.fields?.forEach { field ->
      FieldV2Validator.validate(field)
    }
  }
}

/**
 * FieldV2Validator Validator.
 **/
public object FieldV2Validator {

  /**
   * Validates a FieldV2.
   *
   * This method performs a series of checks to ensure the integrity of the field:
   * 1. Ensures that the field's ID, if present, is not empty.
   * 2. Validates that the purpose, if provided, is not empty.
   * 3. Checks that the name, if present, is not empty.
   * 4. Confirms that the path for the field is not empty.
   * 5. For each path in the field, it verifies the path's validity using JsonPath, and checks for any parsing errors.
   * @throws PexValidationException if the FieldV2 is not valid.
   */
  @Throws(PexValidationException::class)
  public fun validate(field: FieldV2) {
    field.id?.let {
      if (it.isEmpty()) {
        throw PexValidationException("FieldV2 id must not be empty")
      }
    }

    field.purpose?.let {
      if (it.isEmpty()) {
        throw PexValidationException("FieldV2 purpose must not be empty")
      }
    }

    field.name?.let {
      if (it.isEmpty()) {
        throw PexValidationException("FieldV2 name must not be empty")
      }
    }

    if (field.path.isEmpty()) {
      throw PexValidationException("FieldV2 path must not be empty")
    }

    field.path.forEach { path ->
      val result = runCatching { JsonPath(path) }
      if (!result.isSuccess) {
        throw PexValidationException("Invalid JSON path: $path with error message ${result.exceptionOrNull()?.message}")
      }
    }
  }
}

/**
 * PresentationSubmission Validator.
 **/
public object PresentationSubmissionValidator {

  @Throws(PexValidationException::class)

  /**
   * Validates a PresentationSubmission.
   *
   * This method performs several checks to ensure the integrity of the presentation submission model object:
   * 1. Ensures that the presentation submission's id is not empty.
   * 2. Validates that the definitionId is not empty.
   * 3. Validates descriptorMap is a non-empty list.
   * 4. Check for unique inputDescriptor ids at top level
   * 5. Verifies the input descriptor mapping ids are the same on all levels of nesting.
   * 6. Ensures that the path is valid across all levels of nesting
   * @throws PexValidationException if the PresentationDefinitionV2 is not valid.
   */
  public fun validate(presentationSubmission: PresentationSubmission) {
    if (presentationSubmission.id.isEmpty()) {
      throw PexValidationException("PresentationSubmission id must not be empty")
    }

    if (presentationSubmission.definitionId.isEmpty()) {
      throw PexValidationException("PresentationSubmission definitionId must not be empty")
    }

    if (presentationSubmission.descriptorMap.isEmpty()) {
      throw PexValidationException("PresentationSubmission descriptorMap should be a non-empty list")
    }

    // Check for unique inputDescriptor ids
    val ids = presentationSubmission.descriptorMap.map { it.id }
    if (ids.size != ids.toSet().size) {
      throw PexValidationException("All descriptorMap top level ids must be unique")
    }

    validateDescriptorMap(presentationSubmission.descriptorMap)
  }

  private fun validateDescriptorMap(descriptorMap: List<InputDescriptorMapping>) {
    descriptorMap.forEach { descriptor ->
      validateDescriptor(descriptor, descriptor.id)
    }
  }
  private fun validateDescriptor(descriptor: InputDescriptorMapping, id: String?) {
    if (descriptor.id.isEmpty()) {
      throw PexValidationException("Descriptor id should not be empty")
    }

    if (descriptor.path.isEmpty()) {
      throw PexValidationException("Descriptor path should not be empty")
    }

    if (descriptor.format.isEmpty()) {
      throw PexValidationException("Descriptor format should not be empty")
    }

    if (descriptor.id != id) {
      throw PexValidationException("Each descriptor should have one id in it, on all levels")
    }

    if (runCatching { JsonPath(descriptor.path) }.isFailure) {
      throw PexValidationException("Each descriptor should have a valid path id")
    }

    descriptor.pathNested?.let { nestedDescriptor ->
      validateDescriptor(nestedDescriptor, id)
    }
  }
}


