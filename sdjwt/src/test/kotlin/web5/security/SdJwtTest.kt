package web5.security

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.File
import java.io.IOException

val example1 = File("src/test/resources/example1.sdjwt").readText()

class SdJwtTest {
  private val mapper = jacksonObjectMapper().apply {
    enable(SerializationFeature.INDENT_OUTPUT)
    setSerializationInclusion(JsonInclude.Include.NON_NULL)
    setDefaultPrettyPrinter(CustomPrettyPrinter())
  }

  @Test
  fun `parse and serialize are inverse functions`() {
    val sdJwt = SdJwt.parse(example1)
    val serialized = sdJwt.serialize(mapper)
    assertEquals(example1, serialized)
  }

  @Test
  fun `test the mapper serializes objects as expected`() {
    val result = mapper.writeValueAsString(
      mapOf(
        "street_address" to "123 Main St",
        "locality" to "Anytown",
      )
    )
    assertEquals("""{"street_address": "123 Main St", "locality": "Anytown"}""", result)
  }
}

/**
 * A custom printer used for tests.
 */
internal class CustomPrettyPrinter : DefaultPrettyPrinter(
  DefaultPrettyPrinter().withSpacesInObjectEntries().withObjectIndenter(
    NopIndenter.instance
  )
) {
  init {
    this._objectFieldValueSeparatorWithSpaces = this._objectFieldValueSeparatorWithSpaces.substring(1)
  }

  override fun createInstance(): CustomPrettyPrinter {
    check(javaClass == CustomPrettyPrinter::class.java) { // since 2.10
      ("Failed `createInstance()`: " + javaClass.name
        + " does not override method; it has to")
    }
    return CustomPrettyPrinter()
  }

  @Throws(IOException::class)
  override fun writeArrayValueSeparator(g: JsonGenerator) {
    g.writeRaw(_separators.arrayValueSeparator)
    g.writeRaw(' ')
    _arrayIndenter.writeIndentation(g, _nesting)
  }

  @Throws(IOException::class)
  override fun writeObjectEntrySeparator(g: JsonGenerator) {
    g.writeRaw(_separators.objectEntrySeparator)
    g.writeRaw(' ')
    _objectIndenter.writeIndentation(g, _nesting)
  }
}