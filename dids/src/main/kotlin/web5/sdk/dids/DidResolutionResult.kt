package web5.sdk.dids

import foundation.identity.did.DIDDocument

public class DidResolutionResult(
  public var context: String? = null,
  public var didDocument: DIDDocument,
  public var didResolutionMetadata: DidResolutionMetadata = DidResolutionMetadata(),
  public var didDocumentMetadata: DidDocumentMetadata = DidDocumentMetadata()
)

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
