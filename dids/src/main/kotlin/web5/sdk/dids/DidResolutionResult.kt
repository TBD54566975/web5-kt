package web5.sdk.dids

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import web5.sdk.dids.didcore.DIDDocument
import web5.sdk.dids.didcore.DidDocumentMetadata
import java.util.Objects.hash

/**
 * Represents the result of DID resolution as per the W3C DID Core specification.
 * Includes the DID document and related metadata.
 *
 * @property context A URI string that sets the JSON-LD context for the DID document. Optional.
 * @property didDocument The resolved DID document containing a set of assertions made by the DID subject.
 * @property didResolutionMetadata Metadata about the results of the DID resolution process. Optional.
 * @property didDocumentMetadata Metadata about the DID document. Optional.
 */
public class DidResolutionResult(
  @JsonProperty("@context")
  public val context: String? = null,
  public val didDocument: DIDDocument? = null,
  public val didDocumentMetadata: DidDocumentMetadata = DidDocumentMetadata(),
  public val didResolutionMetadata: DidResolutionMetadata = DidResolutionMetadata(),
) {
  override fun toString(): String {
    return objectMapper.writeValueAsString(this)
  }

  override fun equals(other: Any?): Boolean {
    if (other is DidResolutionResult) {
      return this.toString() == other.toString()
    }
    return false
  }

  override fun hashCode(): Int = hash(context, didDocument, didDocumentMetadata, didResolutionMetadata)

  public companion object {
    private val objectMapper: ObjectMapper = ObjectMapper().apply {
      registerModule(KotlinModule.Builder().build())
      setSerializationInclusion(JsonInclude.Include.NON_NULL)
    }


    /**
     * Convenience function that creates a [DidResolutionResult] with [DidResolutionMetadata.error] populated from
     * [error].
     */
    public fun fromResolutionError(error: ResolutionError): DidResolutionResult {
      return DidResolutionResult(
        didResolutionMetadata = DidResolutionMetadata(
          error = error.value
        )
      )
    }
  }
}

/**
 * Holds metadata about the results of the DID resolution process.
 *
 * @property contentType The MIME type of the DID document. This is mandatory unless an error is present.
 * @property error An error message explaining why the DID resolution failed, if applicable.
 * @property additionalProperties Additional properties that may include other DID resolution metadata parameters.
 */
public class DidResolutionMetadata(
  public var contentType: String? = null,
  public var error: String? = null,
  public var additionalProperties: MutableMap<String, Any>? = null,
)


