package web5.sdk.credentials

import assertk.assertFailure
import assertk.assertions.messageContains
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import web5.sdk.credentials.model.PresentationDefinitionV2
import web5.sdk.credentials.model.PresentationSubmission
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.methods.key.DidKey
import web5.sdk.testing.TestVectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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
    fun `throws when we fail to parse the VC`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_sanctions.json"),
        PresentationDefinitionV2::class.java
      )

      val vcJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

      assertThrows<JsonPathParseException> {
        PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd)
      }

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

      assertThrows<IllegalArgumentException> {
        PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd)
      }

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

      assertThrows<IllegalArgumentException> {
        PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd)
      }

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

      assertThrows<IllegalArgumentException> {
        PresentationExchange.satisfiesPresentationDefinition(listOf(vcJwt), pd)
      }

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

  @Nested
  inner class CreatePresentationFromCredentials {
    @Test
    fun `creates valid submission when VC satisfies tbdex PD`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_sanctions.json"),
        PresentationDefinitionV2::class.java
      )

      val presentationSubmission = PresentationExchange.createPresentationFromCredentials(listOf(sanctionsVcJwt), pd)

      assertNotNull(presentationSubmission.id)
      assertEquals(pd.id, presentationSubmission.definitionId)

      assertEquals(1, presentationSubmission.descriptorMap.size)
      assertNotNull(presentationSubmission.descriptorMap[0].id)
      assertEquals("jwt_vc", presentationSubmission.descriptorMap[0].format)
      assertEquals("$.verifiableCredential[0]", presentationSubmission.descriptorMap[0].path)
    }

    @Test
    fun `creates valid submission when VC satisfies PD with no filter dob filed constraint and extra VC`() {
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

      val presentationSubmission = PresentationExchange.createPresentationFromCredentials(listOf(vcJwt2, vcJwt1), pd)

      assertEquals(1, presentationSubmission.descriptorMap.size)
      assertEquals("$.verifiableCredential[1]", presentationSubmission.descriptorMap[0].path)
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
        PresentationExchange.createPresentationFromCredentials(listOf(vcJwt), pd)
      }.messageContains("Missing input descriptors: The presentation definition requires")
    }

    @Test
    fun `creates valid submission when VC two vcs satisfy the same input descriptor`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_path_no_filter_dob.json"),
        PresentationDefinitionV2::class.java
      )

      val vc1 = VerifiableCredential.create(
        type = "DateOfBirth",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "11/11/2011")
      )
      val vcJwt1 = vc1.sign(issuerDid)

      val vc2 = VerifiableCredential.create(
        type = "DateOfBirth",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "12/12/2012")
      )
      val vcJwt2 = vc2.sign(issuerDid)

      val presentationSubmission = PresentationExchange.createPresentationFromCredentials(listOf(vcJwt2, vcJwt1), pd)

      assertEquals(1, presentationSubmission.descriptorMap.size)
      assertEquals("$.verifiableCredential[0]", presentationSubmission.descriptorMap[0].path)
    }
  }

  @Nested
  inner class SelectCredentials {
    @Test
    fun `selects 1 correct credential`() {
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

      val selectedCreds = PresentationExchange.selectCredentials(listOf(vcJwt), pd)

      assertEquals(1, selectedCreds.size)
      assertEquals(vcJwt, selectedCreds[0])
    }

    @Test
    fun `selects 2 correct credential`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_filter_array_single_path.json"),
        PresentationDefinitionV2::class.java
      )

      val vc1 = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt1 = vc1.sign(issuerDid)

      val vc2 = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt2 = vc2.sign(issuerDid)

      val selectedCreds = PresentationExchange.selectCredentials(listOf(vcJwt1, vcJwt2), pd)

      assertEquals(2, selectedCreds.size)
      assertEquals(listOf(vcJwt1, vcJwt2), selectedCreds)
    }

    @Test
    fun `selects 2 correct credential out of 3`() {
      val pd = jsonMapper.readValue(
        readPd("src/test/resources/pd_filter_array_single_path.json"),
        PresentationDefinitionV2::class.java
      )

      val vc1 = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )
      val vcJwt1 = vc1.sign(issuerDid)

      val vc2 = VerifiableCredential.create(
        type = "StreetCred",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = StreetCredibility(localRespect = "high", legit = true)
      )

      val vcJwt2 = vc2.sign(issuerDid)

      val vc3 = VerifiableCredential.create(
        type = "DateOfBirth",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "1-1-1111")
      )

      val vcJwt3 = vc3.sign(issuerDid)

      val selectedCreds = PresentationExchange.selectCredentials(listOf(vcJwt1, vcJwt2, vcJwt3), pd)

      assertEquals(2, selectedCreds.size)
      assertEquals(listOf(vcJwt1, vcJwt2), selectedCreds)
    }

    @Test
    fun `selects 2 correct credential with two input descriptors`() {
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

      val vc2 = VerifiableCredential.create(
        type = "DateOfBirthSSN",
        issuer = issuerDid.uri,
        subject = holderDid.uri,
        data = DateOfBirth(dateOfBirth = "1999-01-01")
      )
      val vcJwt2 = vc2.sign(issuerDid)

      val selectedCreds = PresentationExchange.selectCredentials(listOf(vcJwt1, vcJwt2), pd)

      assertEquals(2, selectedCreds.size)
      assertEquals(listOf(vcJwt1, vcJwt2), selectedCreds)
    }

    @Test
    fun `catches invalid presentation definition`() {
    val pdString = File("src/test/resources/pd_invalid.json").readText().trimIndent()
    val pd = jsonMapper.readValue(pdString, PresentationDefinitionV2::class.java)

      val exception = assertThrows<PexValidationException> {
        PresentationExchange.validateDefinition(pd)
      }

      assertTrue(
        exception
          .message!!.contains("PresentationDefinition id must not be empty")
      )
    }
  }
}


class Web5TestVectorsPresentationExchange {
  data class SelectCredTestInput(
    val presentationDefinition: PresentationDefinitionV2,
    val credentialJwts: List<String>
  )

  data class SelectCredTestOutput(
    val selectedCredentials: List<String>
  )

  private val mapper = jacksonObjectMapper()

  @Test
  fun select_credentials() {
    val typeRef = object : TypeReference<TestVectors<SelectCredTestInput, SelectCredTestOutput>>() {}
    val testVectors =
      mapper.readValue(File("../web5-spec/test-vectors/presentation_exchange/select_credentials.json"), typeRef)

    testVectors.vectors.forEach { vector ->
      val selectedCreds = PresentationExchange.selectCredentials(
        vector.input.credentialJwts,
        vector.input.presentationDefinition
      )
      assertEquals(vector.output!!.selectedCredentials, selectedCreds)
    }
  }

  data class CreatePresFromCredTestInput(
    val presentationDefinition: PresentationDefinitionV2,
    val credentialJwts: List<String>
  )

  data class CreatePresFromCredTestOutput(
    val presentationSubmission: PresentationSubmission
  )

  @Test
  fun create_presentation_from_credentials() {
    val typeRef = object : TypeReference<TestVectors<CreatePresFromCredTestInput, CreatePresFromCredTestOutput>>() {}
    val testVectors = mapper.readValue(
      File("../web5-spec/test-vectors/presentation_exchange/create_presentation_from_credentials.json"),
      typeRef
    )

    testVectors.vectors.forEach { vector ->
      val presSubmission = PresentationExchange.createPresentationFromCredentials(
        vector.input.credentialJwts,
        vector.input.presentationDefinition
      )

      val vectorOutputPresSubmission = vector.output!!.presentationSubmission

      assertEquals(vectorOutputPresSubmission.definitionId, presSubmission.definitionId)
      assertEquals(vectorOutputPresSubmission.descriptorMap.size, presSubmission.descriptorMap.size)

      for (i in vectorOutputPresSubmission.descriptorMap.indices) {
        assertEquals(vectorOutputPresSubmission.descriptorMap[i].id, presSubmission.descriptorMap[i].id)
        assertEquals(vectorOutputPresSubmission.descriptorMap[i].format, presSubmission.descriptorMap[i].format)
        assertEquals(vectorOutputPresSubmission.descriptorMap[i].path, presSubmission.descriptorMap[i].path)
      }
    }
  }


  data class ValidateDefinitionTestInput(
    val presentationDefinition: PresentationDefinitionV2,
    val errors: Boolean
  )

  @Test
  fun validate_definition() {
    val typeRef = object : TypeReference<TestVectors<ValidateDefinitionTestInput, Unit>>() {}
    val testVectors =
      mapper.readValue(File("../web5-spec/test-vectors/presentation_exchange/validate_definition.json"), typeRef)

    testVectors.vectors.filterNot { it.errors ?: false }.forEach { vector ->
      assertDoesNotThrow {
        PresentationExchange.validateDefinition(vector.input.presentationDefinition)
      }
    }

    testVectors.vectors.filter { it.errors ?: false }.forEach { vector ->
      assertFails {
          PresentationExchange.validateDefinition(vector.input.presentationDefinition)
      }
    }
  }

  data class ValidateSubmissionTestInput(
    val presentationSubmission: PresentationSubmission,
    val errors: Boolean
  )
  @Test
  fun validate_submission() {
    val typeRef = object : TypeReference<TestVectors<ValidateSubmissionTestInput, Unit>>() {}
    val testVectors =
      mapper.readValue(File("../web5-spec/test-vectors/presentation_exchange/validate_submission.json"), typeRef)

    testVectors.vectors.filterNot { it.errors ?: false }.forEach { vector ->
      assertDoesNotThrow {
        PresentationExchange.validateSubmission(vector.input.presentationSubmission)
      }
    }

    testVectors.vectors.filter { it.errors ?: false }.forEach { vector ->
      assertFails {
        PresentationExchange.validateSubmission(vector.input.presentationSubmission)
      }
    }
  }
}