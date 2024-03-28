package web5.sdk.jose.jws

import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.common.Json
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.JwaCurve
import web5.sdk.dids.DidResolvers
import web5.sdk.dids.did.BearerDid
import web5.sdk.dids.exceptions.PublicKeyJwkMissingException
import java.security.SignatureException

/**
 * Json Web Signature (JWS) is a compact signature format that is used to secure messages.
 * Spec: https://datatracker.ietf.org/doc/html/rfc7515
 */
public object Jws {

  /**
   * Decode a JWS into its parts.
   *
   * @param jws The JWS to decode
   * @return DecodedJws
   */
  @Suppress("SwallowedException")
  public fun decode(jws: String): DecodedJws {
    val parts = jws.split(".")
    check(parts.size == 3) {
      "Malformed JWT. Expected 3 parts, got ${parts.size}"
    }

    val header: JwsHeader
    try {
      header = JwsHeader.fromBase64Url(parts[0])
    } catch (e: Exception) {
      throw SignatureException("Malformed JWT. Failed to decode header: ${e.message}")
    }

    val payload: ByteArray
    try {
      payload = Convert(parts[1], EncodingFormat.Base64Url).toByteArray()
    } catch (e: Exception) {
      throw SignatureException("Malformed JWT. Failed to decode payload: ${e.message}")
    }

    val signature: ByteArray
    try {
      signature = Convert(parts[2], EncodingFormat.Base64Url).toByteArray()
    } catch (e: Exception) {
      throw SignatureException("Malformed JWT. Failed to decode signature: ${e.message}")
    }

    return DecodedJws(header, payload, signature, parts)
  }

  /**
   * Sign a payload using a Bearer DID.
   *
   * @param bearerDid The Bearer DID to sign with
   * @param payload The payload to sign
   * @param detached Whether to include the payload in the JWS string output
   * @return
   */
  public fun sign(
    bearerDid: BearerDid,
    payload: ByteArray,
    detached: Boolean = false
  ): String {
    val (signer, verificationMethod) = bearerDid.getSigner()

    check(verificationMethod.publicKeyJwk != null) {
      throw PublicKeyJwkMissingException("publicKeyJwk is null.")
    }

    val kid = if (verificationMethod.id.startsWith("#")) {
      "${bearerDid.uri}${verificationMethod.id}"
    } else {
      verificationMethod.id
    }

    val curve = JwaCurve.parse(verificationMethod.publicKeyJwk!!.crv)
    val alg = AlgorithmId.from(curve).name

    val jwsHeader = JwsHeader.Builder()
      .type("JWT")
      .algorithm(alg)
      .keyId(kid)
      .build()

    val headerBase64Url = Convert(Json.stringify(jwsHeader)).toBase64Url()
    val payloadBase64Url = Convert(payload).toBase64Url()

    val toSignBase64Url = "$headerBase64Url.$payloadBase64Url"
    val toSignBytes = Convert(toSignBase64Url).toByteArray()

    val signatureBytes = signer.invoke(toSignBytes)
    val signatureBase64Url = Convert(signatureBytes).toBase64Url()

    return if (detached) {
      "$headerBase64Url..$signatureBase64Url"
    } else {
      "$headerBase64Url.$payloadBase64Url.$signatureBase64Url"
    }

  }

  /**
   * Verify a JWS.
   *
   * @param jws The JWS to verify
   * @return DecodedJws
   */
  public fun verify(jws: String): DecodedJws {
    val decodedJws = decode(jws)
    decodedJws.verify()
    return decodedJws
  }
}

/**
 * JSON Web Signature (JWS) Header Parameters
 *
 * The Header Parameter names for use in JWSs are registered in the IANA "JSON Web Signature and
 * Encryption Header Parameters" registry.
 *
 * Spec: https://datatracker.ietf.org/doc/html/rfc7515
 * @param typ The "typ" (type) Header Parameter is used by JWS applications to declare the media type
 * @param alg The "alg" (algorithm) Header Parameter identifies the cryptographic algorithm used to
 * @param kid The "kid" (key ID) Header Parameter is a hint indicating which key was used to secure
 */
public class JwsHeader(
  public val typ: String? = null,
  public val alg: String? = null,
  public val kid: String? = null
) {

  /**
   * Builder for JwsHeader.
   *
   */
  public class Builder {
    private var typ: String? = null
    private var alg: String? = null
    private var kid: String? = null

    /**
     * Sets the typ field of the JWS header.
     *
     * @param typ The type of the JWS
     * @return Builder object
     */
    public fun type(typ: String): Builder {
      this.typ = typ
      return this
    }

    /**
     * Sets the alg field of the JWS header.
     *
     * @param alg The algorithm used to sign the JWS
     * @return Builder object
     */
    public fun algorithm(alg: String): Builder {
      this.alg = alg
      return this
    }

    /**
     * Sets the kid field of the JWS header.
     *
     * @param kid The key ID used to sign the JWS
     * @return Builder object
     */
    public fun keyId(kid: String): Builder {
      this.kid = kid
      return this
    }

    /**
     * Builds the JwsHeader object.
     *
     * @return JwsHeader
     */
    public fun build(): JwsHeader {
      check(typ != null) { "typ is required" }
      check(alg != null) { "alg is required" }
      check(kid != null) { "kid is required" }
      return JwsHeader(typ, alg, kid)
    }
  }

  public companion object {
    /**
     * Decodes a base64 encoded JWS header.
     *
     * @param base64EncodedHeader The base64 encoded JWS header
     * @return JwsHeader
     */
    public fun fromBase64Url(base64EncodedHeader: String): JwsHeader {
      val jsonHeaderDecoded = Convert(base64EncodedHeader, EncodingFormat.Base64Url).toStr()
      return Json.parse<JwsHeader>(jsonHeaderDecoded)
    }

    /**
     * Encodes a JWS header to base64url string.
     *
     * @param header The JWS header to encode
     * @return String base64url encoded JWS header
     */
    public fun toBase64Url(header: JwsHeader): String {
      val jsonHeader = Json.stringify(header)
      return Convert(jsonHeader, EncodingFormat.Base64Url).toBase64Url()
    }
  }
}

/**
 * DecodedJws is a compact JWS decoded into its parts.
 *
 * @property header The JWS header
 * @property payload The JWS payload
 * @property signature The JWS signature
 * @property parts All parts that make up JWS. Each part is a base64url encoded string
 */
public class DecodedJws(
  public val header: JwsHeader,
  public val payload: ByteArray,
  public val signature: ByteArray,
  public val parts: List<String>
) {

  /**
   * Verify the JWS signature is valid.
   */
  public fun verify() {
    check(header.kid != null || header.alg != null) {
      "Malformed JWS. Expected header to contain kid and alg."
    }

    val didUri = header.kid!!.split("#")[0]
    val resolutionResult = DidResolvers.resolve(didUri)

    check(resolutionResult.didResolutionMetadata.error == null) {
      "Verification failed. Failed to resolve kid. " +
        "Error: ${resolutionResult.didResolutionMetadata.error}"
    }

    check(resolutionResult.didDocument != null) {
      "Verification failed. Expected header kid to dereference a DID document"
    }

    check(resolutionResult.didDocument!!.verificationMethod?.size != 0) {
      "Verification failed. Expected header kid to dereference a verification method"
    }

    val verificationMethod = resolutionResult.didDocument!!.findAssertionMethodById(header.kid)
    check(verificationMethod.publicKeyJwk != null) {
      "Verification failed. Expected headeder kid to dereference" +
        " a verification method with a publicKeyJwk"
    }

    check(verificationMethod.type == "JsonWebKey2020" || verificationMethod.type == "JsonWebKey") {
      "Verification failed. Expected header kid to dereference " +
        "a verification method of type JsonWebKey2020 or JsonWebKey"
    }

    val toSign = "${parts[0]}.${parts[1]}"
    val toSignBytes = Convert(toSign).toByteArray()

    Crypto.verify(verificationMethod.publicKeyJwk!!, toSignBytes, signature)

  }
}