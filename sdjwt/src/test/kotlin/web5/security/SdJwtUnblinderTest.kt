package web5.security

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SdJwtUnblinderTest {
  private val mapper = jacksonObjectMapper().apply {
    enable(SerializationFeature.INDENT_OUTPUT)
    setSerializationInclusion(JsonInclude.Include.NON_NULL)
    setDefaultPrettyPrinter(CustomPrettyPrinter())
  }

  @Test
  fun unblind() {
    val jwtClaimSet = SdJwtUnblinder().unblind(example1)

    val expected = """
      {
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "user_42",
      
        "cnf": {
          "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
          }
        },
        
        "given_name": "John",
        "family_name": "Doe",
        "email": "johndoe@example.com",
        "phone_number": "+1-202-555-0101",
        "phone_number_verified": true,
        "address": {
          "street_address": "123 Main St",
          "locality": "Anytown",
          "region": "Anystate",
          "country": "US"
        },
        "birthdate": "1940-01-01",
        "updated_at": 1570000000,
        "nationalities": [
          "US",
          "DE"
        ]
      }
    """.trimIndent()
    assertEquals(
      JsonCanonicalizer(expected).encodedString,
      JsonCanonicalizer(mapper.writeValueAsString(jwtClaimSet.toJSONObject())).encodedString
    )
  }
}


