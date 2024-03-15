package web5.sdk.crypto.jwk

import web5.sdk.common.Convert
import web5.sdk.common.Json
import java.security.MessageDigest

/**
 * Represents a [JSON Web Key (Jwk )](https://datatracker.ietf.org/doc/html/rfc7517).
 * A Jwk is a JSON object that represents a cryptographic key. This class
 * provides functionalities to manage a Jwk including its creation, conversion
 * to and from JSON, and computing a thumbprint.
 *
 * Example:
 * ```
 * var jwk = Jwk(
 *   kty: 'RSA',
 *   alg: 'RS256',
 *   use: 'sig',
 *   ... // other parameters
 * );
 * ```
 * @property kty Represents the key type.
 * @property use Represents the intended use of the public key.
 * @property alg Identifies the algorithm intended for use with the key.
 * @property kid Key ID, unique identifier for the key.
 * @property crv Elliptic curve name for EC keys.
 * @property d Private key component for EC or OKP keys.
 * @property x X coordinate for EC keys, or the public key for OKP.
 * @property y Y coordinate for EC keys.
 *
 */
public class Jwk(
  public val kty: String,
  public val crv: String,
  public val use: String?,
  public val alg: String?,
  public var kid: String?,
  public val d: String? = null,
  public val x: String?,
  public val y: String?
) {

  /**
   * Computes the thumbprint of the Jwk.
   * [Specification](https://www.rfc-editor.org/rfc/rfc7638.html).
   *
   * Generates a thumbprint of the Jwk using SHA-256 hash function.
   * The thumbprint is computed based on the key's [kty], [crv], [x],
   * and [y] values.
   *
   * @return a Base64URL-encoded string representing the thumbprint.
   */
  public fun computeThumbprint(): String {
    val thumbprintPayload = Json.jsonMapper.createObjectNode().apply {
      put("crv", crv)
      put("kty", kty)
      put("x", x)
      if (y != null) {
        put("y", y)
      }
    }

    val thumbprintPayloadString = Json.stringify(thumbprintPayload)
    val thumbprintPayloadBytes = Convert(thumbprintPayloadString).toByteArray()

    // todo read spec: https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
    val messageDigest = MessageDigest.getInstance("SHA-256")
    val thumbprintPayloadDigest = messageDigest.digest(thumbprintPayloadBytes)

    return Convert(thumbprintPayloadDigest).toBase64Url()

  }

  override fun toString(): String {
    return "Jwk(kty='$kty', use=$use, alg=$alg, kid=$kid, crv=$crv, d=$d, x=$x, y=$y)"
  }

  /**
   * Builder for Jwk type.
   *
   */
  public class Builder {
    // todo take in keytype and curve as required params
    private var kty: String? = null
    private var crv: String? = null
    private var use: String? = null
    private var alg: String? = null
    private var kid: String? = null
    private var d: String? = null
    private var x: String? = null
    private var y: String? = null

    /**
     * Sets key type.
     *
     * @param kty
     * @return Builder object
     */
    public fun keyType(kty: String): Builder {
      this.kty = kty
      return this
    }

    /**
     * Sets key use.
     *
     * @param use
     * @return Builder object
     */
    public fun keyUse(use: String): Builder {
      this.use = use
      return this
    }

    /**
     * Sets algorithm.
     *
     * @param alg
     * @return Builder object
     */
    public fun algorithm(alg: String): Builder {
      this.alg = alg
      return this
    }

    /**
     * Sets key ID.
     *
     * @param kid
     * @return Builder object
     */
    public fun keyId(kid: String): Builder {
      this.kid = kid
      return this
    }

    /**
     * Sets elliptic curve name.
     *
     * @param crv
     * @return Builder object
     */
    public fun curve(crv: String): Builder {
      this.crv = crv
      return this
    }

    /**
     * Sets private key component. Must be base64 encoded string.
     *
     * @param d
     * @return Builder object
     */
    public fun privateKey(d: String): Builder {
      this.d = d
      return this
    }

    /**
     * Sets x coordinate. Must be base64 encoded string.
     *
     * @param x
     * @return Builder object
     */
    public fun x(x: String): Builder {
      this.x = x
      return this
    }

    /**
     * Sets y coordinate. Must be base64 encoded string.
     *
     * @param y
     * @return Builder object
     */
    public fun y(y: String): Builder {
      this.y = y
      return this
    }

    /**
     * Builds a Jwk object.
     *
     * @return Jwk object
     */
    public fun build(): Jwk {
      check(kty != null) { "kty is required" }
      if (kty == "EC") {
        check(x != null) { "x is required for EC keys" }
        check(y != null) { "y is required for EC keys" }
      }
      if (kty == "OKP") {
        check(x != null) { "x is required for OKP keys" }
      }
      // todo crv is required
      return Jwk(kty!!, crv!!, use, alg, kid,  d, x, y)
    }
  }
}
