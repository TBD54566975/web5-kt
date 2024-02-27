package web5.sdk.dids

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.ObjectWriter
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.nimbusds.jose.jwk.JWK
import web5.sdk.dids.didcore.Purpose
import java.io.IOException

/**
 * A singleton for json serialization/deserialization, shared across the SDK as ObjectMapper instantiation
 * is an expensive operation.
 * - Serialize ([stringify])
 *
 * ### Example Usage:
 * ```kotlin
 * val offering = Json.objectMapper.readValue<Offering>(payload)
 *
 * val jsonString = Json.stringify(myObject)
 *
 * val node = Json.parse(payload)
 * ```
 */
public object Json {
  /**
   * The Jackson object mapper instance, shared across the lib.
   *
   * It must be public in order for typed parsing to work as we cannot use reified types for Java interop.
   */
  public val jsonMapper: ObjectMapper = ObjectMapper()
    .registerKotlinModule()
    .findAndRegisterModules()
    .setSerializationInclusion(JsonInclude.Include.NON_NULL)
    .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)

  private val objectWriter: ObjectWriter = jsonMapper.writer()

  /**
   * Converts a kotlin object to a json string.
   *
   * @param obj The object to stringify.
   * @return json string.
   */
  public fun stringify(obj: Any): String {
    return objectWriter.writeValueAsString(obj)
  }
}

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
 * Deserialize String into JWK.
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
