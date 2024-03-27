package web5.sdk.dids.methods.dht

import web5.sdk.dids.didcore.DidDocumentMetadata

/**
 * Did document metadata for did:dht that extends the base did document metadata.
 *
 * @property types list of types
 * @constructor Create empty Did dht document metadata
 */
public class DidDhtDocumentMetadata(
  public val types: List<Int>? = null
) : DidDocumentMetadata()
