package web5.sdk.dids

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import foundation.identity.did.DIDDocument

public class DidResolutionResult(
  public var context: String? = null,
  public var didDocument: DIDDocument,
  public var didResolutionMetadata: DidResolutionMetadata = DidResolutionMetadata(),
  public var didDocumentMetadata: DidDocumentMetadata = DidDocumentMetadata()
) {
  override fun toString(): String {
    return objectMapper.writeValueAsString(this)
  }

  private companion object {
    // Initializing ObjectMapper as a static member
    private val objectMapper: ObjectMapper = ObjectMapper().apply {
      registerModule(KotlinModule.Builder().build())

      setSerializationInclusion(JsonInclude.Include.NON_NULL)
    }
  }
}

public class DidResolutionMetadata(
  public var contentType: String? = null,
  public var error: String? = null,
  public var additionalProperties: MutableMap<String, Any> = mutableMapOf()
)

public class DidDocumentMetadata(
  public var created: String? = null,
  public var updated: String? = null,
  public var deactivated: Boolean? = null,
  public var versionId: String? = null,
  public var nextUpdate: String? = null,
  public var nextVersionId: String? = null,
  public var equivalentId: String? = null,
  public var canonicalId: String? = null,
)
