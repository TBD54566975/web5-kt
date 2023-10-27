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
    val vcJwt =
      "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtrdU5tSmF0ZUNUZXI1V0JycUhCVUM0YUM3TjlOV1NyTURKNmVkQXY1V0NmMiIsInN1YiI6ImRpZDprZXk6ejZNa2t1Tm1KYXRlQ1RlcjVXQnJxSEJVQzRhQzdOOU5XU3JNREo2ZWRBdjVXQ2YyIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiIxNjk4NDIyNDAxMzUyIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlNhbmN0aW9uc0NyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmtleTp6Nk1ra3VObUphdGVDVGVyNVdCcnFIQlVDNGFDN045TldTck1ESjZlZEF2NVdDZjIiLCJpc3N1YW5jZURhdGUiOiIyMDIzLTEwLTI3VDE2OjAwOjAxWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1ra3VObUphdGVDVGVyNVdCcnFIQlVDNGFDN045TldTck1ESjZlZEF2NVdDZjIiLCJiZWVwIjoiYm9vcCJ9fX0.Xhd9nDdkGarYFr6FP7wqsgj5CK3oGTfKU2LHNMvFIsvatgYlSucShDPI8uoeJ_G31uYPke-LJlRy-WVIhkudDg"

    assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(vcJwt, tbdexPd) }
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