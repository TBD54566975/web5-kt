package web5.sdk.crypto.jwk

import web5.sdk.common.Convert
import web5.sdk.common.Json
import java.security.MessageDigest

public class Jwk(
  public val kty: String,
  public val use: String?,
  public val alg: String?,
  public var kid: String?,
  public val crv: String?,
  public val d: String? = null,
  public val x: String?,
  public val y: String?
) {

  public fun computeThumbprint(): String {
    val thumbprintPayload = Json.jsonMapper.createObjectNode().apply {
      put("crv", crv)
      put("kty", kty)
      put("x", x)
      put("y", y)
    }

    val thumbprintPayloadString = Json.stringify(thumbprintPayload)
    val thumbprintPayloadBytes = Convert(thumbprintPayloadString).toByteArray()

    // todo read spec: https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
    val messageDigest = MessageDigest.getInstance("SHA-256")
    val thumbprintPayloadDigest = messageDigest.digest(thumbprintPayloadBytes)

    return Convert(thumbprintPayloadDigest).toBase64Url()

  }

  public class Builder {
    private var kty: String? = null
    private var use: String? = null
    private var alg: String? = null
    private var kid: String? = null
    private var crv: String? = null
    private var d: String? = null
    private var x: String? = null
    private var y: String? = null

    public fun keyType(kty: String): Builder {
      this.kty = kty
      return this
    }

    public fun keyUse(use: String): Builder {
      this.use = use
      return this
    }

    public fun algorithm(alg: String): Builder {
      this.alg = alg
      return this
    }

    public fun keyId(kid: String): Builder {
      this.kid = kid
      return this
    }

    public fun curve(crv: String): Builder {
      this.crv = crv
      return this
    }

    public fun privateKey(d: String): Builder {
      this.d = d
      return this
    }

    public fun x(x: String): Builder {
      this.x = x
      return this
    }

    public fun y(y: String): Builder {
      this.y = y
      return this
    }

    public fun build(): Jwk {
      // todo are any of the other fields required?
      // if kty ec: x y required,
      // if kty ed: x required
      check(kty != null) { "kty is required" }
      return Jwk(kty!!, use, alg, kid, crv, d, x, y)
    }

  }
}
