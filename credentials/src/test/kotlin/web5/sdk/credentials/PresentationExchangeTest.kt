package web5.sdk.credentials

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
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
  private val parsedPd =
    jsonMapper.readValue(PRESENTATION_DEFINITION.trimIndent(), PresentationDefinitionV2::class.java)

  @Test
  fun `satisfiesPresentationDefinition does not throw when VC satisfies requirements`() {
    val vcJwt = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtyM3EyOHlNNDNwVEJUMmFnVkNEZnRMblYzSmdZNktBa2t4aGdOaWY3UGRlayIsInN1YiI6ImRpZDprZXk6ejZNa3IzcTI4eU00M3BUQlQyYWdWQ0RmdExuVjNKZ1k2S0Fra3hoZ05pZjdQZGVrIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiIxNjk4MzY2ODQxODc5IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlNhbmN0aW9uc0NyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmtleTp6Nk1rcjNxMjh5TTQzcFRCVDJhZ1ZDRGZ0TG5WM0pnWTZLQWtreGhnTmlmN1BkZWsiLCJpc3N1YW5jZURhdGUiOiIyMDIzLTEwLTI3VDAwOjM0OjAxWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rcjNxMjh5TTQzcFRCVDJhZ1ZDRGZ0TG5WM0pnWTZLQWtreGhnTmlmN1BkZWsiLCJiZWVwIjoiYm9vcCJ9fX0.DfMnXF5u2PZlHEt_j_Xm42hGXReYG2AC-rMIMeEnFadwzyj5lSZF2qcBuUoX5iA6aMCMS1WrNDcyZNIYNpdMCA"

    assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(vcJwt, parsedPd) }
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

    assertThrows<PresentationExchangeError> { PresentationExchange.satisfiesPresentationDefinition(vcJwt, parsedPd) }
  }

  @Test
  @Disabled
  fun `satisfiesPresentationDefinition returns throws when PD contains submission requirements`() {
    TODO()
  }
}