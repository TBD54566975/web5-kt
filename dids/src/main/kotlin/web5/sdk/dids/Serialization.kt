package web5.sdk.dids

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import web5.sdk.dids.didcore.Purpose
import java.io.IOException

/**
 * Deserialize String into List of Purpose enums.
 *
 */
public class PurposesDeserializer : JsonDeserializer<List<Purpose>>() {
  @Throws(IOException::class, JsonProcessingException::class)
  override fun deserialize(p: JsonParser, ctxt: DeserializationContext): List<Purpose> {
    val node: JsonNode = p.codec.readTree(p)
    return node.mapNotNull { jsonNode ->
      Purpose.fromValue(jsonNode.asText())
    }
  }
}
