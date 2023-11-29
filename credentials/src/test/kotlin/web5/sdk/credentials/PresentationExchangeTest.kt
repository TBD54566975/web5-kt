package web5.sdk.credentials

import assertk.assertFailure
import assertk.assertions.messageContains
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.key.DidKey
import java.io.File
import kotlin.test.Test

data class DateOfBirth(val dateOfBirth: String)
data class Address(val address: String)
data class DateOfBirthSSN(val dateOfBirth: String, val ssn: String)
class PresentationExchangeTest {
  private val keyManager = InMemoryKeyManager()
  private val issuerDid = DidKey.create(keyManager)
  private val holderDid = DidKey.create(keyManager)
  private val jsonMapper: ObjectMapper = ObjectMapper()
    .registerKotlinModule()
    .setSerializationInclusion(JsonInclude.Include.NON_NULL)

  @Suppress("MaximumLineLength")
  val sanctionsVcJwt =
    "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtrdU5tSmF0ZUNUZXI1V0JycUhCVUM0YUM3TjlOV1NyTURKNmVkQXY1V0NmMiIsInN1YiI6ImRpZDprZXk6ejZNa2t1Tm1KYXRlQ1RlcjVXQnJxSEJVQzRhQzdOOU5XU3JNREo2ZWRBdjVXQ2YyIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiIxNjk4NDIyNDAxMzUyIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlNhbmN0aW9uc0NyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmtleTp6Nk1ra3VObUphdGVDVGVyNVdCcnFIQlVDNGFDN045TldTck1ESjZlZEF2NVdDZjIiLCJpc3N1YW5jZURhdGUiOiIyMDIzLTEwLTI3VDE2OjAwOjAxWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1ra3VObUphdGVDVGVyNVdCcnFIQlVDNGFDN045TldTck1ESjZlZEF2NVdDZjIiLCJiZWVwIjoiYm9vcCJ9fX0.Xhd9nDdkGarYFr6FP7wqsgj5CK3oGTfKU2LHNMvFIsvatgYlSucShDPI8uoeJ_G31uYPke-LJlRy-WVIhkudDg"


  private fun readPd(path: String): String {
    return File(path).readText().trimIndent()
  }

  @Nested
  inner class SatisfiesPresentationDefinition {
    @Test
    fun `does not throw when VC satisfies tbdex PD`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_sanctions.json"),
        PresentationDefinitionV2::class.java
      )

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(sanctionsVcJwt), pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with field filter schema on array`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_filter_array.json"),
        PresentationDefinitionV2::class.java
      )
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with field filter schema on array and single path`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_filter_array_single_path.json"),
        PresentationDefinitionV2::class.java
      )
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with field filter schema on value`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_filter_value.json"),
        PresentationDefinitionV2::class.java
      )
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with no filter field constraint`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_path_no_filter.json"),
        PresentationDefinitionV2::class.java
      )
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with no filter dob field constraint`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_path_no_filter_dob.json"),
        PresentationDefinitionV2::class.java
      )

      val vc = VerifiableCredential.create(
        type = "DateOfBirthVc",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "1/1/1111")
      )

      val vcJwt = vc.sign(issuerDid)
      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd) }
    }

    @Test
    fun `does not throw when VC satisfies PD with no filter dob field constraint and extra VC`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_path_no_filter_dob.json"),
        PresentationDefinitionV2::class.java
      )

      val vc1 = VerifiableCredential.create(
        type = "DateOfBirth",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "Data1")
      )
      val vcJwt1 = vc1.sign(issuerDid)

      val vc2 = VerifiableCredential.create(
        type = "Address",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = Address("abc street 123")
      )
      val vcJwt2 = vc2.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt2, vcJwt1), pd) }
    }

    @Test
    fun `does not throw when one VC satisfies both input descriptors PD`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_filter_array_multiple_input_descriptors.json"),
        PresentationDefinitionV2::class.java
      )

      val vc1 = VerifiableCredential.create(
        type = "DateOfBirthSSN",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirthSSN(dateOfBirth = "1999-01-01", ssn = "456-123-123")
      )
      val vcJwt1 = vc1.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt1), pd) }
    }

    @Test
    fun `does not throw when one VC satisfies both input descriptors PD mixed filter`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_mixed_multiple_input_descriptors.json"),
        PresentationDefinitionV2::class.java
      )

      val vc1 = VerifiableCredential.create(
        type = "DateOfBirthSSN",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirthSSN(dateOfBirth = "1999-01-01", ssn = "456-123-123")
      )
      val vcJwt1 = vc1.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt1), pd) }
    }

    @Test
    fun `does not throw when a valid presentation submission has two vc`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_path_no_filter_multiple_input_descriptors.json"),
        PresentationDefinitionV2::class.java
      )

      val vc1 = VerifiableCredential.create(
        type = "DateOfBirthVc",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "1/1/1111")
      )

      val vcJwt1 = vc1.sign(issuerDid)

      val vc2 = VerifiableCredential.create(
        type = "Address",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = Address(address = "123 abc street")
      )

      val vcJwt2 = vc2.sign(issuerDid)

      assertDoesNotThrow { PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt2, vcJwt1), pd) }
    }

    @Test
    fun `throws when VC does not satisfy sanctions requirements`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_sanctions.json"),
        PresentationDefinitionV2::class.java
      )
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertFailure {
        PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd)
      }.messageContains("Missing input descriptors: The presentation definition requires")
    }


    @Test
    fun `throws when VC does not satisfy no filter dob requirements`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_path_no_filter_dob.json"),
        PresentationDefinitionV2::class.java
      )
      val vc = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt = vc.sign(issuerDid)

      assertFailure {
        PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd)
      }.messageContains("Missing input descriptors: The presentation definition requires")
    }

    @Test
    fun `throws when VC does not satisfy filter streetCred requirements`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_filter_array.json"),
        PresentationDefinitionV2::class.java
      )
      val vc = VerifiableCredential.create(
        type = "DateOfBirth",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "01-02-03")
      )
      val vcJwt = vc.sign(issuerDid)

      assertFailure {
        PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd)
      }.messageContains("Missing input descriptors: The presentation definition requires")
    }

    @Test
    fun `throws when VC does not satisfy filter streetCred requirements single path`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_filter_array_single_path.json"),
        PresentationDefinitionV2::class.java
      )
      val vc = VerifiableCredential.create(
        type = "DateOfBirth",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "01-02-03")
      )
      val vcJwt = vc.sign(issuerDid)

      assertFailure {
        PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd)
      }.messageContains("Missing input descriptors: The presentation definition requires")
    }
  }
}