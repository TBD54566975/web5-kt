package web5.sdk.jose

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import web5.sdk.jose.jwt.JwtClaimsSet

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