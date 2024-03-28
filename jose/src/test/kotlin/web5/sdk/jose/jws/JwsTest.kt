package web5.sdk.jose.jws

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertThrows
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.common.Json
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.jwk.DidJwk
import java.security.SignatureException
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNull

class JwsTest {

  @Nested
  inner class DecodeTest {

    @Test
    fun `decode fails if part size less than 3`() {

      assertThrows<IllegalStateException> {
        Jws.decode("a.b.c.d")
      }
    }

    @Test
    fun `decode fails if header is not base64url`() {
      val jwsString = "lol." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

      val exception = assertThrows<SignatureException> {
        Jws.decode(jwsString)
      }
      assertContains(exception.message!!, "Failed to decode header")
    }

    @Test
    fun `decode fails if payload is not base64url`() {
      val jwsString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "{woohoo}." +
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
      val exception = assertThrows<SignatureException> {
        Jws.decode(jwsString)
      }

      assertContains(exception.message!!, "Failed to decode payload")

    }

    @Test
    fun `decode fails if signature is not base64url`() {
      val jwsString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
        "{woot}"

      val exception = assertThrows<SignatureException> {
        Jws.decode(jwsString)
      }

      assertContains(exception.message!!, "Failed to decode signature")
    }

    @Test
    fun `decode fails with test jwt that does not contain header kid`() {
      val jwsString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

      val exception = assertThrows<IllegalStateException> {
        Jws.decode(jwsString)
      }

      assertContains(exception.message!!, "Expected header to contain kid")
    }
    @Test
    fun `decode succeeds with test jwt`() {
      val jwsString = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaU" +
        "xDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbWRsWjI5YWNuWTVjemxuVWtwT1praFBlVGt5Tm" +
        "1oa1drNTBVMWxZWjJoaFlsOVJSbWhGTlRNM1lrMGlmUSMwIiwidHlwIjoiSldUIn0" +
        ".eyJpc3MiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2ll" +
        "Q0k2SW1kbFoyOWFjblk1Y3psblVrcE9aa2hQZVRreU5taGtXazUwVTFsWVoyaGhZbDlSUm1oRk5UTT" +
        "NZazBpZlEiLCJqdGkiOiJ1cm46dmM6dXVpZDpjNWMzZGExMi02ODhmLTQxZDYtOTQzMC1lYzViNDAy" +
        "NTFmMzMiLCJuYmYiOjE3MTE2NTA4MjcsInN1YiI6IjEyMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHB" +
        "zOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZW" +
        "RlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU" +
        "5URTVJaXdpZUNJNkltZGxaMjlhY25ZNWN6bG5Va3BPWmtoUGVUa3lObWhrV2s1MFUxbFlaMmhoWWw5UlJ" +
        "taEZOVE0zWWswaWZRIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiIxMjMifSwiaWQiOiJ1cm46dmM" +
        "6dXVpZDpjNWMzZGExMi02ODhmLTQxZDYtOTQzMC1lYzViNDAyNTFmMzMiLCJpc3N1YW5jZURhdGUiOiIy" +
        "MDI0LTAzLTI4VDE4OjMzOjQ3WiJ9fQ" +
        ".ydUiwf33dDCdk4RyPfoTdgbK3yTUpLCDpPBIECbn-rCGn_W3q5QxzAt43ClOIWibpOXHs-9T86UDBFPyd79vAQ"

      val decodedJws = Jws.decode(jwsString)

      assertEquals("EdDSA", decodedJws.header.alg)
      assertEquals("JWT", decodedJws.header.typ)
      val payloadStr = Convert(decodedJws.payload).toStr()
      val payload = Json.parse<Map<String, Any>>(payloadStr)
      assertEquals(
        "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Imdl" +
          "Z29acnY5czlnUkpOZkhPeTkyNmhkWk50U1lYZ2hhYl9RRmhFNTM3Yk0ifQ",
        payload["iss"]
      )
      assertEquals(1711650827, payload["nbf"])
      assertEquals(
        "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Imdl" +
          "Z29acnY5czlnUkpOZkhPeTkyNmhkWk50U1lYZ2hhYl9RRmhFNTM3Yk0ifQ",
        decodedJws.signerDid
      )
      assertEquals(3, decodedJws.parts.size)

    }

    @Test
    fun `decode succeeds with detached payload`() {
      val jwsStringWithoutPayload = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaU" +
        "xDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbWRsWjI5YWNuWTVjemxuVWtwT1praFBlVGt5Tm" +
        "1oa1drNTBVMWxZWjJoaFlsOVJSbWhGTlRNM1lrMGlmUSMwIiwidHlwIjoiSldUIn0" +
        "..ydUiwf33dDCdk4RyPfoTdgbK3yTUpLCDpPBIECbn-rCGn_W3q5QxzAt43ClOIWibpOXHs-9T86UDBFPyd79vAQ"

      val payloadBase64Url = "eyJpc3MiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2ll" +
        "Q0k2SW1kbFoyOWFjblk1Y3psblVrcE9aa2hQZVRreU5taGtXazUwVTFsWVoyaGhZbDlSUm1oRk5UTT" +
        "NZazBpZlEiLCJqdGkiOiJ1cm46dmM6dXVpZDpjNWMzZGExMi02ODhmLTQxZDYtOTQzMC1lYzViNDAy" +
        "NTFmMzMiLCJuYmYiOjE3MTE2NTA4MjcsInN1YiI6IjEyMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHB" +
        "zOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZW" +
        "RlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU" +
        "5URTVJaXdpZUNJNkltZGxaMjlhY25ZNWN6bG5Va3BPWmtoUGVUa3lObWhrV2s1MFUxbFlaMmhoWWw5UlJ" +
        "taEZOVE0zWWswaWZRIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiIxMjMifSwiaWQiOiJ1cm46dmM" +
        "6dXVpZDpjNWMzZGExMi02ODhmLTQxZDYtOTQzMC1lYzViNDAyNTFmMzMiLCJpc3N1YW5jZURhdGUiOiIy" +
        "MDI0LTAzLTI4VDE4OjMzOjQ3WiJ9fQ"
      val payloadBytes = Convert(payloadBase64Url, EncodingFormat.Base64Url).toByteArray()
      val decodedJws = Jws.decode(jwsStringWithoutPayload, payloadBytes)

      assertEquals("EdDSA", decodedJws.header.alg)
      assertEquals("JWT", decodedJws.header.typ)
      val payloadStr = Convert(decodedJws.payload).toStr()
      val payload = Json.parse<Map<String, Any>>(payloadStr)
      assertEquals(
        "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Imdl" +
          "Z29acnY5czlnUkpOZkhPeTkyNmhkWk50U1lYZ2hhYl9RRmhFNTM3Yk0ifQ",
        payload["iss"]
      )
      assertEquals(1711650827, payload["nbf"])
      assertEquals(
        "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Imdl" +
          "Z29acnY5czlnUkpOZkhPeTkyNmhkWk50U1lYZ2hhYl9RRmhFNTM3Yk0ifQ",
        decodedJws.signerDid
      )
      assertEquals(3, decodedJws.parts.size)
    }
  }

  @Nested
  inner class SignTest {

    @Test
    fun `sign successfully creates signedJws`() {
      val bearerDid = DidJwk.create(InMemoryKeyManager())
      val payload = "hello".toByteArray()

      val signedJws = Jws.sign(bearerDid, payload)

      val parts = signedJws.split(".")
      assertEquals(3, parts.size)
      val headerString = Convert(parts[0], EncodingFormat.Base64Url).toStr()
      val header = Json.parse<JwsHeader>(headerString)
      assertEquals("JWT", header.typ)
      assertEquals("Ed25519", header.alg)
      assertEquals(bearerDid.document.verificationMethod?.first()?.id, header.kid)
      val decodedPayload = Convert(parts[1], EncodingFormat.Base64Url).toStr()
      assertEquals("hello", decodedPayload)

    }

    @Test
    fun `sign successfully creates detached signedJws`() {
      val bearerDid = DidJwk.create(InMemoryKeyManager())
      val payload = "hello".toByteArray()

      val signedJws = Jws.sign(bearerDid, payload, detached = true)

      val parts = signedJws.split(".")
      assertEquals(3, parts.size)
      val headerString = Convert(parts[0], EncodingFormat.Base64Url).toStr()
      val header = Json.parse<JwsHeader>(headerString)
      assertEquals("JWT", header.typ)
      assertEquals("Ed25519", header.alg)
      assertEquals(bearerDid.document.verificationMethod?.first()?.id, header.kid)
      assertEquals("", parts[1])
    }

  }
}