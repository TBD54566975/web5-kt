package web5.sdk.jose.jwt

import com.fasterxml.jackson.databind.JsonNode
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.common.Json
import web5.sdk.dids.did.BearerDid
import web5.sdk.jose.jws.DecodedJws
import web5.sdk.jose.jws.Jws
import web5.sdk.jose.jws.JwsHeader

/**
 * Json Web Token (JWT) is a compact, URL-safe means of representing claims to be transferred between two parties.
 * Spec: https://datatracker.ietf.org/doc/html/rfc7519
 */
public object Jwt {

  /**
   * Decode a JWT into its parts.
   *
   * @param jwt The JWT string to decode
   * @return DecodedJwt
   */
  @Suppress("SwallowedException")
  public fun decode(jwt: String): DecodedJwt {
    val decodedJws = Jws.decode(jwt)

    val claims: JwtClaimsSet
    try {
      val payload = Convert(decodedJws.payload).toStr()
      val decodedPayload = Convert(payload, EncodingFormat.Base64Url).toStr()
      claims = JwtClaimsSet.fromJson(Json.jsonMapper.readTree(decodedPayload))
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

  /**
   * Sign a JwtClaimsSet using a Bearer DID.
   *
   * @param did The Bearer DID to sign with
   * @param payload The JwtClaimsSet payload to sign
   * @return The signed JWT
   */
  public fun sign(did: BearerDid, payload: JwtClaimsSet): String {
    val header = JwtHeader(typ = "JWT")
    val payloadBytes = Convert(Json.stringify(payload)).toByteArray()

    return Jws.sign(did, payloadBytes, header)
  }

  /**
   * Verify a JWT.
   *
   * @param jwt The JWT to verify
   * @return DecodedJwt
   */
  public fun verify(jwt: String): DecodedJwt {
    val decodedJwt = decode(jwt)
    decodedJwt.verify()
    return decodedJwt
  }
}

/**
 * DecodedJwt is a compact JWT decoded into its parts.
 *
 * @property header The JWT header
 * @property claims The JWT claims
 * @property signature The JWT signature
 * @property parts The JWT parts
 */
public class DecodedJwt(
  public val header: JwtHeader,
  public val claims: JwtClaimsSet,
  public val signature: ByteArray,
  public val parts: List<String>
) {
  /**
   * Verifies the JWT.
   *
   */
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

/**
 * Claims represents JWT (JSON Web Token) Claims
 * Spec: https://datatracker.ietf.org/doc/html/rfc7519#section-4
 *
 * @property iss identifies the principal that issued the
 * @property sub the principal that is the subject of the JWT.
 * @property aud the recipients that the JWT is intended for.
 * @property exp the expiration time on or after which the JWT must not be accepted for processing.
 * @property nbf the time before which the JWT must not be accepted for processing.
 * @property iat the time at which the JWT was issued.
 * @property jti provides a unique identifier for the JWT.
 * @property misc additional claims (i.e. VerifiableCredential, VerifiablePresentation)
 */
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

    /**
     * Takes a JsonNode representation of a claim and builds a JwtClaimsSet.
     *
     * @param jsonNode The JsonNode representation of a claim
     * @return JwtClaimsSet
     */
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

  /**
   * Builder for JwtClaimsSet.
   *
   */
  public class Builder {
    private var iss: String? = null
    private var sub: String? = null
    private var aud: String? = null
    private var exp: Long? = null
    private var nbf: Long? = null
    private var iat: Long? = null
    private var jti: String? = null
    private var misc: MutableMap<String, Any> = mutableMapOf()

    /**
     * Sets Issuer (iss) claim.
     *
     * @param iss The principal that issued the JWT
     * @return Builder object
     */
    public fun issuer(iss: String): Builder = apply { this.iss = iss }

    /**
     * Sets Subject (sub) claim.
     *
     * @param sub The principal that is the subject of the JWT
     * @return Builder object
     */
    public fun subject(sub: String): Builder = apply { this.sub = sub }

    /**
     * Sets Audience (aud) claim.
     *
     * @param aud The recipients that the JWT is intended for
     * @return Builder object
     */
    public fun audience(aud: String): Builder = apply { this.aud = aud }

    /**
     * Sets Expiration Time (exp) claim.
     *
     * @param exp The expiration time on or after which the JWT must not be accepted for processing
     * @return Builder object
     */
    public fun expirationTime(exp: Long): Builder = apply { this.exp = exp }

    /**
     * Sets Not Before (nbf) claim.
     *
     * @param nbf The time before which the JWT must not be accepted for processing
     * @return Builder object
     */
    public fun notBeforeTime(nbf: Long): Builder = apply { this.nbf = nbf }

    /**
     * Sets Issued At (iat) claim.
     *
     * @param iat The time at which the JWT was issued
     * @return Builder object
     */
    public fun issueTime(iat: Long): Builder = apply { this.iat = iat }

    /**
     * Sets JWT ID (jti) claim.
     *
     * @param jti The unique identifier for the JWT
     * @return Builder object
     */
    public fun jwtId(jti: String): Builder = apply { this.jti = jti }

    /**
     * Sets a custom claim.
     *
     * @param key The key of the custom claim
     * @param value The value of the custom claim
     * @return Builder object
     */
    public fun misc(key: String, value: Any): Builder = apply { this.misc[key] = value }

    /**P
     * Builds the JwtClaimsSet object.
     *
     * @return JwtClaimsSet
     */
    public fun build(): JwtClaimsSet = JwtClaimsSet(iss, sub, aud, exp, nbf, iat, jti, misc)
  }
}
