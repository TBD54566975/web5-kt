package web5.sdk.dids

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.nimbusds.jose.jwk.JWK
import web5.sdk.dids.didcore.Purpose
import java.io.IOException

/**
 * Serialize JWK into String.
 */
public class JWKSerializer : JsonSerializer<JWK?>() {
  public override fun serialize(jwk: JWK?, gen: JsonGenerator, serializers: SerializerProvider?) {
    val jwkString = jwk?.toJSONString()

    gen.writeRawValue(jwkString)
  }

}

/**
 * Deserialize String into JWK.
 *
 */
public class JwkDeserializer : JsonDeserializer<JWK>() {
  override fun deserialize(p: JsonParser, ctxt: DeserializationContext): JWK {
    val node = p.codec.readTree<JsonNode>(p)
    val jwkJson = node.toString()
    return JWK.parse(jwkJson)
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
