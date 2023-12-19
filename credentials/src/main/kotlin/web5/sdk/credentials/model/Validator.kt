package web5.sdk.credentials.model

import com.fasterxml.jackson.databind.JsonNode
import com.nfeld.jsonpathkt.JsonPath
import com.nfeld.jsonpathkt.extension.read
import web5.sdk.credentials.JsonPathParseException

/**
 * PresentationDefinitionV2Validator Validator.
 **/
public object PresentationDefinitionV2Validator {

  /**
   * Validates a PresentationDefinitionV2.
   */
  public fun validate(presentationDefinition: PresentationDefinitionV2) {
    require(presentationDefinition.id.isNotEmpty()) { "PresentationDefinition id must not be empty" }
    presentationDefinition.name?.let { require(it.isNotEmpty()) {
      "PresentationDefinition name must not be empty" }
    }
    presentationDefinition.purpose?.let { require(it.isNotEmpty()) {
      "PresentationDefinition purpose must not be empty" }
    }

    // Check for unique inputDescriptor IDs
    val ids = presentationDefinition.inputDescriptors.map { it.id }
    require(ids.size == ids.toSet().size) { "All inputDescriptor ids must be unique" }

    // Check for unique FieldV2 ids across all input descriptors
    val fieldIds = presentationDefinition.inputDescriptors.flatMap {
      it.constraints.fields?.mapNotNull { field -> field.id } ?: listOf()
    }

    require(fieldIds.size == fieldIds.toSet().size) {
      "Field ids must be unique across all input descriptors"
    }

    presentationDefinition.inputDescriptors.forEach { descriptor ->
      InputDescriptorV2Validator.validate(descriptor)
    }

    presentationDefinition.frame?.let { FrameValidator.validate(presentationDefinition.frame) }
  }

}

/**
 * InputDescriptorV2Validator Validator.
 **/
public object InputDescriptorV2Validator {

  /**
   * Validates a InputDescriptorV2.
   */
  public fun validate(inputDescriptor: InputDescriptorV2) {
    require(inputDescriptor.id.isNotEmpty()) { "InputDescriptor id must not be empty" }
    inputDescriptor.name?.let { require(it.isNotEmpty()) { "InputDescriptor name must not be empty" } }
    inputDescriptor.purpose?.let { require(it.isNotEmpty()) { "InputDescriptor purpose must not be empty" } }

    inputDescriptor.constraints.fields?.forEach {
      field ->
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
   */
  public fun validate(field: FieldV2) {
    field.id?.let { require(it.isNotEmpty()) { "FieldV2 id must not be empty" } }
    field.purpose?.let { require(it.isNotEmpty()) { "FieldV2 purpose must not be empty" } }
    field.name?.let { require(it.isNotEmpty()) { "FieldV2 name must not be empty" } }

    require(field.path.isNotEmpty()) { "FieldV2 path must not be empty" }

    field.path.forEach { path ->
      val result = runCatching { JsonPath(path) }
      require(result.isSuccess) { "Invalid JSON path: $path with error message ${result.exceptionOrNull()?.message}" }
    }
  }
}

/**
 * FrameValidator Validator.
 **/
public object FrameValidator {

  /**
   * Validates a Frame.
   */
  public fun validate(frame: Map<String, Any>) {
    require(frame.isNotEmpty()) { "Frame cannot be empty" }

    frame["@id"]?.let {
      require(validateFrameProperty(it, "Frame @id must be a wildcard or an IRI"))
    }

    frame["@types"]?.let {
      require(validateFrameProperty(it, "Frame @types must be a wildcard or an IRI"))
    }
  }

  private fun validateFrameProperty(property: Any, errorMessage: String): Boolean {
    val values = asArray(property)
    values.forEach { value ->
      require(isValidFrameValue(value)) { errorMessage }
    }
    return true
  }

  private fun asArray(value: Any): List<Any?> = if (value is Collection<*>) value.toList() else listOf(value)

  private fun isValidFrameValue(value: Any?): Boolean =
    when (value) {
      is Map<*, *> -> true
      is String -> !value.startsWith("_:")
      else -> false
    }
}
