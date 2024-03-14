package web5.sdk.jose.jwt

import com.fasterxml.jackson.databind.JsonNode
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.common.Json
import web5.sdk.dids.did.BearerDid
import web5.sdk.jose.jws.DecodedJws
import web5.sdk.jose.jws.Jws
import web5.sdk.jose.jws.JwsHeader

public object Jwt {

  public fun decode(jwt: String): DecodedJwt {
    val decodedJws = Jws.decode(jwt)

    val claims: JwtClaimsSet
    try {
      val payload = Convert(decodedJws.payload).toStr()
      claims = JwtClaimsSet.fromJson(Json.jsonMapper.readTree(payload))
    } catch (e: Exception) {
      throw IllegalArgumentException(
        "Malformed JWT. " +
          "Invalid base64url encoding for JWT payload. ${e.message}"
      )
    }

    return DecodedJwt(
      header = decodedJws.header,
      claims = claims,
      signature = decodedJws.signature,
      parts = decodedJws.parts
    )

  }

  public fun sign(did: BearerDid, payload: JwtClaimsSet): String {
    val header = JwtHeader(typ = "JWT")
    val payloadBytes = Convert(Json.stringify(payload)).toByteArray()

    return Jws.sign(did, payloadBytes, header)
  }

  public fun verify(jwt: String): DecodedJwt {
    val decodedJwt = decode(jwt)
    decodedJwt.verify()
    return decodedJwt
  }
}

public class DecodedJwt(
  public val header: JwtHeader,
  public val claims: JwtClaimsSet,
  public val signature: ByteArray,
  public val parts: List<String>
) {
  public fun verify() {
    val decodedJws = DecodedJws(
      header = header,
      payload = Convert(parts[1], EncodingFormat.Base64Url).toByteArray(),
      signature = signature,
      parts = parts
    )
    decodedJws.verify()
  }
}

public typealias JwtHeader = JwsHeader

public class JwtClaimsSet(
  public val iss: String? = null,
  public val sub: String? = null,
  public val aud: String? = null,
  public val exp: Long? = null,
  public val nbf: Long? = null,
  public val iat: Long? = null,
  public val jti: String? = null,
  public val misc: Map<String, Any> = emptyMap()
) {
  public companion object {
    public fun fromJson(jsonNode: JsonNode): JwtClaimsSet {
      val reservedClaims = setOf(
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti"
      )

      val miscClaims: MutableMap<String, Any> = mutableMapOf()

      val fields = jsonNode.fields()
      while (fields.hasNext()) {
        val (key, value) = fields.next()
        if (!reservedClaims.contains(key)) {
          miscClaims[key] = value
        }
      }

      return JwtClaimsSet(
        iss = jsonNode.get("iss")?.asText(),
        sub = jsonNode.get("sub")?.asText(),
        aud = jsonNode.get("aud")?.asText(),
        exp = jsonNode.get("exp")?.asLong(),
        nbf = jsonNode.get("nbf")?.asLong(),
        iat = jsonNode.get("iat")?.asLong(),
        jti = jsonNode.get("jti")?.asText(),
        misc = miscClaims
      )

    }
  }

  public class Builder {
    private var iss: String? = null
    private var sub: String? = null
    private var aud: String? = null
    private var exp: Long? = null
    private var nbf: Long? = null
    private var iat: Long? = null
    private var jti: String? = null
    private var misc: MutableMap<String, Any> = mutableMapOf()

    public fun issuer(iss: String): Builder = apply { this.iss = iss }
    public fun subject(sub: String): Builder = apply { this.sub = sub }
    public fun audience(aud: String): Builder = apply { this.aud = aud }
    public fun expirationTime(exp: Long): Builder = apply { this.exp = exp }
    public fun notBeforeTime(nbf: Long): Builder = apply { this.nbf = nbf }
    public fun issueTime(iat: Long): Builder = apply { this.iat = iat }
    public fun jwtId(jti: String): Builder = apply { this.jti = jti }
    public fun misc(key: String, value: Any): Builder = apply { this.misc[key] = value }

    public fun build(): JwtClaimsSet = JwtClaimsSet(iss, sub, aud, exp, nbf, iat, jti, misc)
  }
}
