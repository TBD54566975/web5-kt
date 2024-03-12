package web5.sdk.dids.jws

import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.common.Json
import web5.sdk.crypto.Crypto
import web5.sdk.dids.DidResolvers
import web5.sdk.dids.did.BearerDid
import web5.sdk.dids.exceptions.PublicKeyJwkMissingException

public object Jws {

  public fun decode(jws: String): DecodedJws {
    val parts = jws.split(".")
    check(parts.size != 3) {
      "Malformed JWT. Expected 3 parts, got ${parts.size}"
    }

    val header: JwsHeader
    try {
      header = JwsHeader.fromBase64Url(parts[0])
    } catch (e: Exception) {
      throw IllegalArgumentException("Malformed JWT. Failed to decode header: ${e.message}")
    }

    val payload: ByteArray
    try {
      payload = Convert(parts[1]).toByteArray()
    } catch (e: Exception) {
      throw IllegalArgumentException("Malformed JWT. Failed to decode payload: ${e.message}")
    }

    val signature: ByteArray
    try {
      signature = Convert(parts[2]).toByteArray()
    } catch (e: Exception) {
      throw IllegalArgumentException("Malformed JWT. Failed to decode signature: ${e.message}")
    }

    return DecodedJws(header, payload, signature, parts)
  }

  public fun sign(
    bearerDid: BearerDid,
    payload: ByteArray,
    header: JwsHeader?,
    detached: Boolean = false
  ): String {
    val (signer, verificationMethod) = bearerDid.getSigner()

    check(verificationMethod.publicKeyJwk != null) {
      throw PublicKeyJwkMissingException("publicKeyJwk is null.")
    }

    val kid = if (verificationMethod.id.startsWith("#")) {
      "${bearerDid.did.uri}${verificationMethod.id}"
    } else {
      verificationMethod.id
    }

    val jwsHeader = header
      ?: JwsHeader.Builder()
        .type("JWT")
        .keyId(kid)
        // todo pretty sure i need algorithm names like ES256K for secp and EdDSA for ed25519
        .algorithm(Crypto.getJwkCurve(verificationMethod.publicKeyJwk)?.name!!)
        .build()

    val headerBase64Url = Convert(jwsHeader).toBase64Url()
    val payloadBase64Url = Convert(payload).toBase64Url()

    val toSign = "$headerBase64Url.$payloadBase64Url"
    val toSignBytes = Convert(toSign).toByteArray()

    val signatureBytes = signer.invoke(toSignBytes)
    val signatureBase64Url = Convert(signatureBytes).toBase64Url()

    return if (detached) {
      "$headerBase64Url..$signatureBase64Url"
    } else {
      "$headerBase64Url.$payloadBase64Url.$signatureBase64Url"
    }

  }

  public fun verify(jws: String): DecodedJws {
    val decodedJws = decode(jws)
    decodedJws.verify()
    return decodedJws
  }
}

public class JwsHeader(
  public val typ: String? = null,
  public val alg: String? = null,
  public val kid: String? = null
) {

  public fun toBase64Url(): String {
    return toBase64Url(this)
  }

  public class Builder {
    private var typ: String? = null
    private var alg: String? = null
    private var kid: String? = null

    public fun type(typ: String): Builder {
      this.typ = typ
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

    public fun build(): JwsHeader {
      check(typ != null) { "typ is required" }
      check(alg != null) { "alg is required" }
      check(kid != null) { "kid is required" }
      return JwsHeader(typ, alg, kid)
    }
  }

  public companion object {
    // todo do i need these toJson and fromJson?
    // i could just call Json.jsonMapper.xyz()
    public fun toJson(header: JwsHeader): String {
      return Json.stringify(header)
    }

    public fun fromJson(jsonHeader: String): JwsHeader {
      return Json.parse<JwsHeader>(jsonHeader)
    }

    public fun fromBase64Url(base64EncodedHeader: String): JwsHeader {
      val jsonHeaderDecoded = Convert(base64EncodedHeader, EncodingFormat.Base64Url).toStr()
      return Json.parse<JwsHeader>(jsonHeaderDecoded)
    }

    public fun toBase64Url(header: JwsHeader): String {
      val jsonHeader = toJson(header)
      return Convert(jsonHeader, EncodingFormat.Base64Url).toBase64Url()
    }
  }
}

public class DecodedJws(
  public val header: JwsHeader,
  public val payload: ByteArray,
  public val signature: ByteArray,
  public val parts: List<String>
) {
  public fun verify() {
    check(header.kid != null || header.alg != null) {
      "Malformed JWS. Expected header to contain kid and alg."
    }

    val dereferenceResult = DidResolvers.resolve(header.kid!!)

    check(dereferenceResult.didResolutionMetadata.error != null) {
      "Verification failed. Failed to resolve kid. " +
        "Error: ${dereferenceResult.didResolutionMetadata.error}"
    }

    check(dereferenceResult.didDocument!!.verificationMethod?.size != 0) {
      "Verification failed. Expected header kid to dereference a verification method"
    }

    /*
    // todo
    in JwtUtil, we had this
    val verificationMethodIds = setOf(
      did.url,
      "#${did.fragment}"
    )
    and were checking the assertionMethod list for a match of the id
    and then find the vm that matches the id
    but here we are just looking for the first?
     */
    val verificationMethod = dereferenceResult.didDocument.verificationMethod!!.first()
    check(verificationMethod.publicKeyJwk != null) {
      "Verification failed. Expected headeder kid to dereference" +
        " a verification method with a publicKeyJwk"
    }

    // todo add this bit in coz it was in JwtUtil.verify()
    check(verificationMethod.type == "JsonWebKey2020" || verificationMethod.type == "JsonWebKey") {
      "Verification failed. Expected header kid to dereference " +
        "a verification method of type JsonWebKey2020 or JsonWebKey"
    }

    val toSign = "${parts[0]}.${parts[1]}"
    val toSignBytes = Convert(toSign).toByteArray()

    Crypto.verify(verificationMethod.publicKeyJwk, toSignBytes, signature)

  }
}