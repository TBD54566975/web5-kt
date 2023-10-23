package web5.sdk.dids

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.erdtman.jcs.JsonCanonicalizer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

class DidResolutionResultTest {
  @Test
  fun `parsing and serializing a DidResolutionResult is idempotent`() {
    val mapper = jacksonObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)

    val expectedJson = File("src/test/resources/expected_long_form_did_resolution.json").readText()
    val parsedResult: DidResolutionResult = mapper.readValue(expectedJson)
    val jsonValue = mapper.writeValueAsString(parsedResult)

    assertEquals(
      JsonCanonicalizer(expectedJson).encodedString,
      JsonCanonicalizer(jsonValue).encodedString,
    )
  }
}