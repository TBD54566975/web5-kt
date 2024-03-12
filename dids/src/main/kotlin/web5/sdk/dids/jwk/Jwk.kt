package web5.sdk.dids.jwk

import web5.sdk.common.Convert
import web5.sdk.common.Json
import java.security.MessageDigest

public class Jwk(
  public val kty: String,
  public val use: String?,
  public val alg: String?,
  kid: String?,
  public val crv: String?,
  public val d: String? = null,
  public val x: String?,
  public val y: String?,
  kidFromThumbprint: Boolean = true
) {

  public val kid: String? = kid ?: if (kidFromThumbprint) computeThumbprint() else null

  private fun computeThumbprint(): String {
    val thumbprintPayload = Json.jsonMapper.createObjectNode().apply {
      put("crv", crv)
      put("kty", kty)
      put("x", x)
      put("y", y)
    }

    // todo this is what chad told me to do, not sure 100% correct
    val thumbprintPayloadString = Json.stringify(thumbprintPayload)
    val thumbprintPayloadBytes = Convert(thumbprintPayloadString).toByteArray()

    // todo what does this do? supposed to be the equivalent of
    //  final thumbprintPayloadDigest = _dartSha256.hashSync(thumbprintPayloadBytes);
    val messageDigest = MessageDigest.getInstance("SHA-256")
    val thumbprintPayloadDigest = messageDigest.digest(thumbprintPayloadBytes)

    return Convert(thumbprintPayloadDigest).toBase64Url()

  }


}
