package web5.sdk.credentials

import assertk.assertThat
import assertk.assertions.contains
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.junit.jupiter.api.Test

class PresentationDefinitionTest {
  val jsonMapper: ObjectMapper = ObjectMapper()
    .registerKotlinModule()
    .findAndRegisterModules()
    .setSerializationInclusion(JsonInclude.Include.NON_NULL)
  @Test
  fun `can serialize`() {
    val pd = PresentationDefinitionV2(
      id = "test-pd-id",
      name = "simple PD",
      purpose = "pd for testing",
      inputDescriptors = listOf()
    )

    val serializedPd = jsonMapper.writeValueAsString(pd)

    assertThat(serializedPd).contains("input_descriptors")
  }

  @Test
  fun `can deserialize`() {
    val pdString = """
      {
          "id": "398f69f3-a3d4-4fb1-939a-82281671f7e5",
          "input_descriptors": [
              {
                  "id": "0edade78-ed51-44ae-a0fd-5636372c0978",
                  "constraints": {
                      "fields": [
                          {
                              "path": [
                                  "${'$'}.issuer"
                              ],
                              "filter": {
                                  "type": "string",
                                  "const": "did:ion:EiD6Jcwrqb5lFLFWyW59uLizo5lBuChieiqtd0TFN0xsng:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJ6cC1mNnFMTW1EazZCNDFqTFhIXy1kd0xOLW9DS2lTcDJaa19WQ2t4X3ZFIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6IjNmVFk3VXpBaU9VNVpGZ05VVjl3bm5pdEtGQk51RkNPLWxlRXBDVzhHOHMiLCJ5IjoidjJoNlRqTDF0TnYwSDNWb09Fbll0UVBxRHZOVC0wbVdZUUdLTGRSakJ3ayJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV0sInNlcnZpY2VzIjpbXX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQjk3STI2bmUwdkhXYXduODk1Y1dnVlE0cFF5NmN1OUFlSzV2aW44X3JVeXcifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaURqSmlEdm9RekstRl94V05VVzlzMTBUVmlpdEI0Z1JoS09iYlh2S1pwdlNRIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCbEk1NWx6b3JoeE42TVBqUlZtV2ZZY3MxNzNKOFk3S0hTeU5LcmZiTzVfdyJ9fQ"
                              }
                          },
                          {
                              "path": [
                                  "${'$'}.type[*]"
                              ],
                              "filter": {
                                  "type": "string",
                                  "pattern": "^SanctionCredential${'$'}"
                              }
                          }
                      ]
                  }
              }
          ]
      }
    """.trimIndent()

    val deserializedPd = jsonMapper.readValue(pdString, PresentationDefinitionV2::class.java)

  }
}