package web5.sdk.dids

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import web5.sdk.common.Json
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.didcore.Purpose
import java.io.IOException

// todo delete the de/serializers for jwk
/**
 * Serialize Jwk into String.
 */
public class JwkSerializer : JsonSerializer<Jwk?>() {
  public override fun serialize(jwk: Jwk?, gen: JsonGenerator, serializers: SerializerProvider?) {
    val jwkString = jwk?.let { Json.stringify(it) }
    gen.writeRawValue(jwkString)
  }

}

/**
 * Deserialize String into Jwk.
 *
 */
public class JwkDeserializer : JsonDeserializer<Jwk>() {
  override fun deserialize(p: JsonParser, ctxt: DeserializationContext): Jwk {
    val node = p.codec.readTree<JsonNode>(p)
    val jwkJson = node.toString()
    return Json.parse<Jwk>(jwkJson)
  }
}

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
