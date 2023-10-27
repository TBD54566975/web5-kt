package web5.sdk.credentials

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.assertThrows
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.DidKey
import kotlin.test.Test
import kotlin.test.assertFalse

class PresentationExchangeTest {
  private val keyManager = InMemoryKeyManager()
  private val issuerDid = DidKey.create(keyManager)
  private val holderDid = DidKey.create(keyManager)
  private val jsonMapper: ObjectMapper = ObjectMapper()
    .registerKotlinModule()
    .findAndRegisterModules()
    .setSerializationInclusion(JsonInclude.Include.NON_NULL)
  private val parsedPd =
    jsonMapper.readValue(PRESENTATION_DEFINITION.trimIndent(), PresentationDefinitionV2::class.java)

  @Test
  @Disabled
  fun `satisfiesPresentationDefinition returns true when VC satisfies requirements`() {
    TODO()
  }

  @Test
  fun `satisfiesPresentationDefinition returns false when VC does not satisfy requirements`() {
    val vc = VerifiableCredential.create(
      type = "StreetCred",
      issuer = issuerDid.uri,
      subject = holderDid.uri,
      data = StreetCredibility(localRespect = "high", legit = true)
    )
    val vcJwt = vc.sign(issuerDid)

    assertThrows<PresentationExchangeError> { PresentationExchange.satisfiesPresentationDefinition(vcJwt, parsedPd) }
  }

  @Test
  @Disabled
  fun `satisfiesPresentationDefinition returns throws when PD contains submission requirements`() {
    TODO()
  }

  @Test
  @Disabled
  fun `satisfiesPresentationDefinition returns throws when PD fields contain filter schemas`() {
    TODO()
  }
}