package web5.sdk.credentials

import assertk.assertFailure
import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.messageContains
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.credentials.model.ConstraintsV2
import web5.sdk.credentials.model.FieldV2
import web5.sdk.credentials.model.InputDescriptorV2
import web5.sdk.credentials.model.PresentationDefinitionV2
import java.io.File

class PresentationDefinitionTest {
  val jsonMapper: ObjectMapper = ObjectMapper()
    .registerKotlinModule()
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

  @Test
  fun `is valid`() {
    val pdString = File("src/test/resources/pd_sanctions.json").readText().trimIndent()
    val pd = jsonMapper.readValue(pdString, PresentationDefinitionV2::class.java)
    assertDoesNotThrow { PresentationExchange.validateDefinition(pd) }
  }

  @Test
  fun `is invalid with all inputDescriptor ids must be unique`() {
    val pd = PresentationDefinitionV2(
      id = "test-pd-id",
      inputDescriptors = listOf(
        InputDescriptorV2(
          id = "id-123",
          constraints = ConstraintsV2(
            fields = listOf()
          )
        ),
        InputDescriptorV2(
          id = "id-123",
          constraints = ConstraintsV2(
            fields = listOf()
          )
        )
      )
    )

    assertFailure {
      PresentationExchange.validateDefinition(pd)
    }.messageContains("All inputDescriptor ids must be unique")
  }

  @Test
  fun `is invalid with all field ids must be unique`() {
    val factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7)
    val filter = factory.getSchema(
      """
      {"type":"string","const":"123"}
    """.trimIndent()
    )

    val pd = PresentationDefinitionV2(
      id = "test-pd-id",
      inputDescriptors = listOf(
        InputDescriptorV2(
          id = "id-1",
          constraints = ConstraintsV2(
            fields = listOf(
              FieldV2(
                id = "field-id",
                path = listOf("$.issuer"),
                filterJson = filter.schemaNode
              )
            )
          )
        ),
        InputDescriptorV2(
          id = "id-2",
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

    assertFailure {
      PresentationExchange.validateDefinition(pd)
    }.messageContains("Field ids must be unique across all input descriptors")
  }

  @Test
  fun `is invalid with path being empty`() {
    val factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7)
    val filter = factory.getSchema(
      """
      {"type":"string","const":"123"}
    """.trimIndent()
    )

    val pd = PresentationDefinitionV2(
      id = "test-pd-id",
      inputDescriptors = listOf(
        InputDescriptorV2(
          id = "id-1",
          constraints = ConstraintsV2(
            fields = listOf(
              FieldV2(
                id = "field-id",
                path = listOf(),
                filterJson = filter.schemaNode
              )
            )
          )
        )
      )
    )

    assertFailure {
      PresentationExchange.validateDefinition(pd)
    }.messageContains("FieldV2 path must not be empty")
  }

  @Test
  fun `is invalid with invalid json paths`() {
    val factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7)
    val filter = factory.getSchema(
      """
      {"type":"string","const":"123"}
    """.trimIndent()
    )

    val invalidPath = "$.store.book[(@.price == 10]"  // Missing closing parenthesis

    val pd = PresentationDefinitionV2(
      id = "test-pd-id",
      inputDescriptors = listOf(
        InputDescriptorV2(
          id = "id-1",
          constraints = ConstraintsV2(
            fields = listOf(
              FieldV2(
                id = "field-id",
                path = listOf(invalidPath),
                filterJson = filter.schemaNode
              )
            )
          )
        )
      )
    )

    assertFailure {
      PresentationExchange.validateDefinition(pd)
    }.messageContains("Invalid JSON path")
  }
}