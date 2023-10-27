package web5.sdk.credentials

import assertk.assertThat
import assertk.assertions.contains
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import java.io.File

class PresentationDefinitionTest {
  val jsonMapper: ObjectMapper = ObjectMapper()
    .registerKotlinModule()
    .findAndRegisterModules()
    .setSerializationInclusion(JsonInclude.Include.NON_NULL)

  @Test
  fun `can serialize`() {
    val factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7)
    val filter = factory.getSchema(
      """
      {"type":"string","const":"123"}
    """.trimIndent()
    )
    val pd = PresentationDefinitionV2(
      id = "test-pd-id",
      name = "simple PD",
      purpose = "pd for testing",
      inputDescriptors = listOf(
        InputDescriptorV2(
          id = "whatever",
          purpose = "purpose",
          constraints = ConstraintsV2(
            fields = listOf(
              FieldV2(
                id = "field-id",
                path = listOf("$.issuer"),
                filterJson = filter.schemaNode
              )
            )
          )
        )
      )
    )
    val serializedPd = jsonMapper.writeValueAsString(pd)

    assertThat(serializedPd).contains("input_descriptors")
    assertThat(serializedPd).contains("123")
  }

  @Test
  fun `serialization is idempotent`(){
    val pdString = File("src/test/resources/pd_sanctions.json").readText().trimIndent()
    val parsedPd = jsonMapper.readValue(pdString, PresentationDefinitionV2::class.java)
    val parsedString = jsonMapper.writeValueAsString(parsedPd)

    assertEquals(
      JsonCanonicalizer(pdString).encodedString,
      JsonCanonicalizer(parsedString).encodedString,
    )
  }

  @Test
  fun `can deserialize`() {
    val pdString = File("src/test/resources/pd_sanctions.json").readText().trimIndent()

    assertDoesNotThrow { jsonMapper.readValue(pdString, PresentationDefinitionV2::class.java) }
  }
}