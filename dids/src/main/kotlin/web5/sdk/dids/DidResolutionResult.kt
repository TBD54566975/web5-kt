package web5.sdk.dids

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import foundation.identity.did.DIDDocument
import web5.sdk.dids.methods.ion.models.MetadataMethod
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

/**
 * Contains metadata about the DID document.
 *
 * @property created Timestamp of when the DID was created.
 * @property updated Timestamp of the last time the DID was updated.
 * @property deactivated Indicates whether the DID has been deactivated. `true` if deactivated, `false` otherwise.
 * @property versionId Specific version of the DID document.
 * @property nextUpdate Timestamp of the next expected update of the DID document.
 * @property nextVersionId The version ID expected for the next version of the DID document.
 * @property equivalentId Alternative ID that can be used interchangeably with the canonical DID.
 * @property canonicalId The canonical ID of the DID as per method-specific rules.
 * @property types Returns types for DIDs that support type indexing.
 */
public class DidDocumentMetadata(
  public var created: String? = null,
  public var updated: String? = null,
  public var deactivated: Boolean? = null,
  public var versionId: String? = null,
  public var nextUpdate: String? = null,
  public var nextVersionId: String? = null,
  public var equivalentId: List<String>? = null,
  public var canonicalId: String? = null,
  public val method: MetadataMethod? = null,
  public val types: List<Int>? = null
)

