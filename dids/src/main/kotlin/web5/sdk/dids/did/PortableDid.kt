package web5.sdk.dids.did

import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.didcore.DidDocument

/**
 * PortableDid is a serializable BearerDid that documents the key material and metadata
 * of a Decentralized Identifier (DID) to enable usage of the DID in different contexts.
 *
 * This format is useful for exporting, saving to a file, or importing a DID across process
 * boundaries or between different DID method implementations.
 *
 * @property uri The URI of the DID.
 * @property privateKeys The private keys associated with the PortableDid.
 * @property document The DID Document associated with the PortableDid.
 * @property metadata Additional metadata associated with the PortableDid.
 */
public class PortableDid(
  public val uri: String,
  public val privateKeys: List<Jwk>,
  public val document: DidDocument,
  public val metadata: Map<String, Any>
  )