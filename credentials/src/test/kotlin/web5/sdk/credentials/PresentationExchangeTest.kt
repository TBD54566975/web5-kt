package web5.sdk.credentials

import assertk.assertFailure
import assertk.assertions.messageContains
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
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
  private val tbdexPd =
    jsonMapper.readValue(TBDEX_PD.trimIndent(), PresentationDefinitionV2::class.java)

  @Test
  fun `satisfiesPresentationDefinition does not throw when VC satisfies requirements`() {
    assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(VC_JWT, tbdexPd) }
  }

  @Test
  fun `satisfiesPresentationDefinition throws when VC does not satisfy requirements`() {
    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true)
    )
    val vcJwt = vc.sign(issuerDid)

    assertFailure {
      PresentationExchange.satisfiesPresentationDefinition(vcJwt, tbdexPd)
    }.messageContains("validating [\"VerifiableCredential\",\"StreetCred\"] failed")
  }
}