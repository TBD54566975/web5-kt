package web5.sdk.credentials

import assertk.assertFailure
import assertk.assertions.messageContains
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.DidKey
import kotlin.test.Test

class PresentationExchangeTest {
  private val keyManager = InMemoryKeyManager()
  private val issuerDid = DidKey.create(keyManager)
  private val holderDid = DidKey.create(keyManager)
  private val jsonMapper: ObjectMapper = ObjectMapper()
    .registerKotlinModule()
    .findAndRegisterModules()
    .setSerializationInclusion(JsonInclude.Include.NON_NULL)

  @Nested
  inner class SatisfiesPresentationDefinition {
    @Test
    fun `does not throw when VC satisfies tbdex PD`() {
      val pd =
        jsonMapper.readValue(SANCTIONS_PD.trimIndent(), PresentationDefinitionV2::class.java)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(SANCTIONS_VC_JWT, pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with field filter schema on array`() {
      val pd =
        jsonMapper.readValue(PD_FILTER_ARRAY.trimIndent(), PresentationDefinitionV2::class.java)
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(vcJwt, pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with field filter schema on value`() {
      val pd =
        jsonMapper.readValue(PD_FILTER_VALUE.trimIndent(), PresentationDefinitionV2::class.java)
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(vcJwt, pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with field constraint`() {
      val pd =
        jsonMapper.readValue(PD_PATH_NO_FILTER.trimIndent(), PresentationDefinitionV2::class.java)
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(vcJwt, pd) }
    }

    @Test
    fun `throws when VC does not satisfy requirements`() {
      val pd =
        jsonMapper.readValue(SANCTIONS_PD.trimIndent(), PresentationDefinitionV2::class.java)
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertFailure {
        PresentationExchange.satisfiesPresentationDefinition(vcJwt, pd)
      }.messageContains("Validating [\"VerifiableCredential\",\"StreetCred\"]")
    }
  }
}