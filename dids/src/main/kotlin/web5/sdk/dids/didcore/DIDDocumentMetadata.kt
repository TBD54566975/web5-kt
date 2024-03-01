package web5.sdk.dids.didcore

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
 */
public class DidDocumentMetadata(
  public var created: String? = null,
  public var updated: String? = null,
  public var deactivated: Boolean? = null,
  public var versionId: String? = null,
  public var nextUpdate: String? = null,
  public var nextVersionId: String? = null,
  public var equivalentId: String? = null,
  public var canonicalId: String? = null,
  // todo only did dht uses this field? pull out into DidDhtDocumentMetadata?
  public val types: List<Int>? = null
)
