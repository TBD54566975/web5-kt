package web5.sdk.dids.did

import com.nimbusds.jose.jwk.JWK
import web5.sdk.dids.didcore.DidDocument

public class PortableDid(
  public val uri: String,
  public val privateKeys: List<JWK>,
  public val document: DidDocument,
  public val metadata: Map<String, Any>
  )