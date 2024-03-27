package web5.sdk.jose

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import web5.sdk.common.Json
import web5.sdk.jose.jwt.JwtClaimsSet

/**
 * JwtClaimsSet serializer.
 *
 * Used to serialize JwtClaimsSet into a JSON object that flattens the misc claims
 *
 */
public class JwtClaimsSetSerializer : JsonSerializer<JwtClaimsSet>() {

  override fun serialize(jwtClaimsSet: JwtClaimsSet, gen: JsonGenerator, serializers: SerializerProvider?) {
    gen.writeStartObject()

    jwtClaimsSet.iss?.let { gen.writeStringField("iss", it) }
    jwtClaimsSet.sub?.let { gen.writeStringField("sub", it) }
    jwtClaimsSet.aud?.let { gen.writeStringField("aud", it) }
    jwtClaimsSet.exp?.let { gen.writeNumberField("exp", it) }
    jwtClaimsSet.nbf?.let { gen.writeNumberField("nbf", it) }
    jwtClaimsSet.iat?.let { gen.writeNumberField("iat", it) }
    jwtClaimsSet.jti?.let { gen.writeStringField("jti", it) }

    for ((key, value) in jwtClaimsSet.misc) {
      gen.writeObjectField(key, value)
    }

    gen.writeEndObject()
  }

}

/**
 * JwtClaimsSet deserializer.
 *
 * Used to deserialize JSON object JwtClaimsSet
 * that takes miscellaneous claims and puts them as values inside misc key
 */
public class JwtClaimsSetDeserializer : JsonDeserializer<JwtClaimsSet>() {
  public override fun deserialize(p: JsonParser, ctxt: DeserializationContext): JwtClaimsSet {
    val jsonNode = p.codec.readTree<JsonNode>(p)
    val reservedClaims = setOf(
      "iss",
      "sub",
      "aud",
      "exp",
      "nbf",
      "iat",
      "jti"
    )

    // extract misc nodes
    val miscClaims = Json.jsonMapper.createObjectNode()
    val fields = jsonNode.fields()

    while (fields.hasNext()) {
      val (key, value) = fields.next()

      if (!reservedClaims.contains(key)) {
        miscClaims.set<JsonNode>(key, value)
      }
    }

    val miscClaimsMap = Json.jsonMapper.convertValue(miscClaims, Map::class.java)

    return JwtClaimsSet(
      iss = jsonNode.get("iss")?.asText(),
      sub = jsonNode.get("sub")?.asText(),
      aud = jsonNode.get("aud")?.asText(),
      exp = jsonNode.get("exp")?.asLong(),
      nbf = jsonNode.get("nbf")?.asLong(),
      iat = jsonNode.get("iat")?.asLong(),
      jti = jsonNode.get("jti")?.asText(),
      misc = miscClaimsMap as Map<String, Any>
    )
  }
}