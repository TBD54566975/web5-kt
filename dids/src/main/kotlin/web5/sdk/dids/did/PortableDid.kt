package web5.sdk.dids.did

import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.didcore.DidDocument

public class PortableDid(
  public val uri: String,
  public val privateKeys: List<Jwk>,
  public val document: DidDocument,
  public val metadata: Map<String, Any>
  )