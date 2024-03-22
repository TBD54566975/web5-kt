package web5.sdk.crypto.jwk

import org.junit.jupiter.api.Test
import web5.sdk.crypto.JwaCurve
import kotlin.test.assertEquals

class JwkTest {

  @Test
  fun `computeThumbPrint works with secp256k1 jwk`() {
    val jwk = Jwk.Builder(keyType = "EC", curve = JwaCurve.secp256k1.name)
      .x("vdrbz2EOzvbLDV_-kL4eJt7VI-8TFZNmA9YgWzvhh7U")
      .y("VLFqQMZP_AspucXoWX2-bGXpAO1fQ5Ln19V5RAxrgvU")
      .algorithm("ES256K")
      .build()

    val thumbprint = jwk.computeThumbprint()

    assertEquals("i3SPRBtJKovHFsBaqM92ti6xQCJLX3E7YCewiHV2CSg", thumbprint)

  }

  @Test
  fun `computeThumbprint works with Ed25519 jwk`() {
    val jwk = Jwk.Builder(keyType = "OKP", curve = JwaCurve.Ed25519.name)
      .x("DzpSEyU0w1Myn3lA_piHAI6OrFAnZuEsTwMUPCTwMc8")
      .algorithm("EdDSA")
      .build()

    val thumbprint = jwk.computeThumbprint()

    assertEquals("c4IOrQdnehPwQZ6SyNLp9J942VCXrxgWw4zUxAHQXQE", thumbprint)
  }

}