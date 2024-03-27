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
    fun `decode succeeds with test jwt from jwtio`() {
      val jwsString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

      val decodedJws = Jws.decode(jwsString)

      assertEquals("HS256", decodedJws.header.alg)
      assertEquals("JWT", decodedJws.header.typ)
      val payloadStr = Convert(decodedJws.payload).toStr()
      val payload = Json.parse<Map<String, Any>>(payloadStr)
      assertEquals("1234567890", payload["sub"])
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