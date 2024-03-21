package web5.sdk.jose.jwt

import org.junit.jupiter.api.Nested
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.jwk.DidJwk
import kotlin.test.Test
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
  }

}