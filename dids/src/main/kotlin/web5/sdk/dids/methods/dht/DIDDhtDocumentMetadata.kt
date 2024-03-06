package web5.sdk.dids.methods.dht

import web5.sdk.dids.didcore.DIDDocumentMetadata

/**
 * Did document metadata for did:dht that extends the base did document metadata.
 *
 * @property types list of types
 * @constructor Create empty Did dht document metadata
 */
public class DIDDhtDocumentMetadata(
  public val types: List<Int>? = null
) : DIDDocumentMetadata()
