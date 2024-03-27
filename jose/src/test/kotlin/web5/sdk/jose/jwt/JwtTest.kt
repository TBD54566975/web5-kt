package web5.sdk.jose.jwt

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.jwk.DidJwk
import java.security.SignatureException
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals

class JwtTest {

  @Nested
  inner class DecodeTest {

    @Test
    fun `decode succeeds`() {
      val bearerDid = DidJwk.create(InMemoryKeyManager())
      val claims = JwtClaimsSet.Builder()
        .issuer("me")
        .subject("you")
        .misc("vc", mapOf("type" to listOf("VerifiableCredential")))
        .build()
      val vcJwt = Jwt.sign(bearerDid, claims)

      val decodedJwt = Jwt.decode(vcJwt)
      assertEquals(bearerDid.document.verificationMethod?.first()?.id, decodedJwt.header.kid)
      assertEquals(claims.toString(), decodedJwt.claims.toString())
    }

    @Test
    fun `decode fails due to payload failing and throws exception`() {
      val vcJwt =
        "eyJraWQiOiJkaWQ6a2V5OnpRM3NoTkx0MWFNV1BiV1JHYThWb2VFYkpvZko3" +
          "eEplNEZDUHBES3hxMU5aeWdwaXkjelEzc2hOTHQxYU1XUGJXUkdhOFZvZU" +
          "ViSm9mSjd4SmU0RkNQcERLeHExTlp5Z3BpeSIsInR5cCI6IkpXVCIsImFsZ" +
          "yI6IkVTMjU2SyJ9.hehe.qoqF4-FinFsQ2J-NFSO46xCE8kUTZqZCU5fYr6t" +
          "S0TQ6VP8y-ZnyR6R3oAqLs_Yo_CqQi23yi38uDjLjksiD2w"

      val exception = assertThrows<SignatureException> { Jwt.decode(vcJwt) }

      assertContains(exception.message!!, "Malformed JWT. Invalid base64url encoding for JWT payload.")
    }
  }

  @Nested
  inner class SignTest {

    @Test
    fun `sign succeeds`() {
      val bearerDid = DidJwk.create(InMemoryKeyManager())
      val claims = JwtClaimsSet.Builder()
        .issuer("me")
        .subject("you")
        .misc("vc", mapOf("type" to listOf("VerifiableCredential")))
        .build()

      assertDoesNotThrow { Jwt.sign(bearerDid, claims) }
    }
  }

}