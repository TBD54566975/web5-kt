package web5.sdk.dids.did

import com.nimbusds.jose.jwk.JWK
import web5.sdk.dids.didcore.DIDDocument

public class PortableDID(
  public val uri: String,
  public val privateKeys: List<JWK>,
  public val document: DIDDocument,
  public val metadata: Map<String, Any>
  )