package web5.security

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.crypto.impl.ECDSAProvider
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.DidKey

class SdJwtSignerTest {

  private val mapper = jacksonObjectMapper().apply {
    enable(SerializationFeature.INDENT_OUTPUT)
    setSerializationInclusion(JsonInclude.Include.NON_NULL)
    setDefaultPrettyPrinter(CustomPrettyPrinter())
  }

  @Test
  fun testExample1() {
    val claims = """{
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
      
      "updated_at": 1570000000,
      "email": "johndoe@example.com",
      "phone_number": "+1-202-555-0101",
      "family_name": "Doe",
      "phone_number_verified": true,
      "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US"
      },
      "birthdate": "1940-01-01",
      "given_name": "John",
      "nationalities": [
        "US",
        "DE"
      ]
    }""".trimIndent()

    val keyManager = InMemoryKeyManager()
    val issuerSigner = DidKey.create(keyManager)

    val signer = SdJwtSigner(
      saltGenerator = MockMapGenerator(
        mapOf(
          "given_name" to "2GLC42sKQveCfGfryNRN9w",
          "family_name" to "eluV5Og3gSNII8EYnsxA_A",
          "email" to "6Ij7tM-a5iVPGboS5tmvVA",
          "phone_number" to "eI8ZWm9QnKPpNPeNenHdhQ",
          "phone_number_verified" to "Qg_O64zqAxe412a108iroA",
          "address" to "AJx-095VPrpTtN4QMOqROA",
          "birthdate" to "Pc33JM2LchcU_lHggv_ufQ",
          "updated_at" to "G02NSrQfjFXQ7Io09syajA",
          "nationalities[0]" to "lklxF5jMYlGTPUovMNIvCA",
          "nationalities[1]" to "nPuoQnkRFq3BIeAm7AnXFA",
        )
      ),
      signer = KeyManagerSigner(keyManager, keyManager.getDeterministicAlias(publicKey = getPublicKey(issuerSigner))),
      shuffle = {},
      totalDigests = { i -> i },
      mapper = mapper,
    )
    // Define claims to blind
    // The nationalities array is always visible, but its contents are selectively disclosable.
    // The sub element and essential verification data (iss, iat, cnf, etc.) are always visible.
    // All other End-User claims are selectively disclosable.
    // For address, the Issuer is using a flat structure, i.e., all of the claims in the address claim can only be disclosed in full. Other options are discussed in Section 5.7.
    val claimsToBlind = mapOf(
      "given_name" to FlatBlindOption,
      "family_name" to FlatBlindOption,
      "email" to FlatBlindOption,
      "phone_number" to FlatBlindOption,
      "phone_number_verified" to FlatBlindOption,
      "address" to FlatBlindOption,
      "birthdate" to FlatBlindOption,
      "updated_at" to FlatBlindOption,
      "nationalities" to ArrayBlindOption,
    )

    val sdJwt = signer.blindAndSign(claims, claimsToBlind, JWSAlgorithm.ES256K, getPublicKey(issuerSigner).keyID)

    val expected = """{
      "_sd": [
        "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI",
        "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE",
        "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI",
        "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
        "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM",
        "XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE",
        "gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM",
        "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"
      ],
      "iss": "https://example.com/issuer",
      "iat": 1683000000,
      "exp": 1883000000,
      "sub": "user_42",
      "nationalities": [
        {
          "...": "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"
        },
        {
          "...": "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"
        }
      ],
      "_sd_alg": "sha-256",
      "cnf": {
        "jwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
          "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        }
      }
    }""".trimIndent()

    val givenNameActualDisclosure = sdJwt.disclosures.find { disclosure ->
      (disclosure as? ObjectDisclosure)?.let { it.claimName == "given_name" } ?: false
    } as ObjectDisclosure
    assertEquals("2GLC42sKQveCfGfryNRN9w", givenNameActualDisclosure.salt)
    assertEquals("John", givenNameActualDisclosure.claimValue)
    assertEquals(
      JsonCanonicalizer(expected).encodedString,
      JsonCanonicalizer(mapper.writeValueAsString(sdJwt.issuerJwt.jwtClaimsSet.toJSONObject())).encodedString
    )
  }

  @Test
  fun `test option 1`() {
    val keyManager = InMemoryKeyManager()
    val issuerSigner = DidKey.create(keyManager)

    val signer = SdJwtSigner(
      saltGenerator = MockMapGenerator(
        mapOf(
          "address" to "2GLC42sKQveCfGfryNRN9w"
        )
      ),
      signer = KeyManagerSigner(keyManager, keyManager.getDeterministicAlias(publicKey = getPublicKey(issuerSigner))),
      totalDigests = { i -> i },
      mapper = mapper,
    )

    // Define claims as a JSON string
    val claims = """{
      "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      "address": {
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": "DE"
      },
      "iss": "https://example.com/issuer",
      "iat": 1683000000,
      "exp": 1883000000
    }""".trimIndent()

    // Define claims to blind
    val claimsToBlind = mapOf(
      "address" to FlatBlindOption,
    )

    val sdJwt = signer.blindAndSign(claims, claimsToBlind, JWSAlgorithm.ES256K, getPublicKey(issuerSigner).keyID)

    val expected = """{
      "_sd": [
        "fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do"
      ],
      "iss": "https://example.com/issuer",
      "iat": 1683000000,
      "exp": 1883000000,
      "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      "_sd_alg": "sha-256"
    }""".trimIndent()

    assertEquals(
      JsonCanonicalizer(expected).encodedString,
      JsonCanonicalizer(mapper.writeValueAsString(sdJwt.issuerJwt.jwtClaimsSet.toJSONObject())).encodedString
    )
  }

  @Test
  fun `test option 2`() {
    val keyManager = InMemoryKeyManager()
    val issuerSigner = DidKey.create(keyManager)

    val signer = SdJwtSigner(
      saltGenerator = MockMapGenerator(
        mapOf(
          "street_address" to "2GLC42sKQveCfGfryNRN9w",
          "locality" to "eluV5Og3gSNII8EYnsxA_A",
          "region" to "6Ij7tM-a5iVPGboS5tmvVA",
          "country" to "eI8ZWm9QnKPpNPeNenHdhQ"
        )
      ),
      shuffle = {},
      signer = KeyManagerSigner(keyManager, keyManager.getDeterministicAlias(publicKey = getPublicKey(issuerSigner))),
      totalDigests = { i -> i },
      mapper = mapper,
    )

    // Define claims as a JSON string
    val claims = """{
      "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      "address": {
        "locality": "Schulpforta",
        "street_address": "Schulstr. 12",
        "region": "Sachsen-Anhalt",
        "country": "DE"
      },
      "iss": "https://example.com/issuer",
      "iat": 1683000000,
      "exp": 1883000000
    }""".trimIndent()

    // Define claims to blind
    val claimsToBlind = mapOf(
      "address" to SubClaimBlindOption(
        mapOf(
          "street_address" to FlatBlindOption,
          "locality" to FlatBlindOption,
          "region" to FlatBlindOption,
          "country" to FlatBlindOption,
        )
      ),
    )

    val sdJwt = signer.blindAndSign(claims, claimsToBlind, JWSAlgorithm.ES256K, getPublicKey(issuerSigner).keyID)

    val expected = """{
      "iss": "https://example.com/issuer",
      "iat": 1683000000,
      "exp": 1883000000,
      "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      "address": {
        "_sd": [
          "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
          "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
          "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
          "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM"
        ]
      },
      "_sd_alg": "sha-256"
    }""".trimIndent()

    assertEquals(
      JsonCanonicalizer(expected).encodedString,
      JsonCanonicalizer(mapper.writeValueAsString(sdJwt.issuerJwt.jwtClaimsSet.toJSONObject())).encodedString
    )
  }

  @Test
  // https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-option-3-sd-jwt-with-recurs
  fun `test option 3`() {
    val keyManager = InMemoryKeyManager()
    val issuerSigner = DidKey.create(keyManager)

    val signer = SdJwtSigner(
      saltGenerator = MockMapGenerator(
        mapOf(
          "street_address" to "2GLC42sKQveCfGfryNRN9w",
          "locality" to "eluV5Og3gSNII8EYnsxA_A",
          "region" to "6Ij7tM-a5iVPGboS5tmvVA",
          "country" to "eI8ZWm9QnKPpNPeNenHdhQ",
          "address" to "Qg_O64zqAxe412a108iroA",
        )
      ),
      shuffle = {},
      signer = KeyManagerSigner(keyManager, keyManager.getDeterministicAlias(publicKey = getPublicKey(issuerSigner))),
      totalDigests = { i -> i },
      mapper = mapper,
    )

    // Define claims as a JSON string
    val claims = """{
      "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      "address": {
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": "DE"
      },
      "iss": "https://example.com/issuer",
      "iat": 1683000000,
      "exp": 1883000000
    }""".trimIndent()

    // Define claims to blind
    val claimsToBlind = mapOf(
      "address" to RecursiveBlindOption
    )

    val sdJwt = signer.blindAndSign(claims, claimsToBlind, JWSAlgorithm.ES256K, getPublicKey(issuerSigner).keyID)

    val expected = """{
      "_sd": [
        "dQ8wNyUukwFtQFG1LpY4_P4Vfy6Mnk9PUa2YC2C2Fvw"
      ],
      "iss": "https://example.com/issuer",
      "iat": 1683000000,
      "exp": 1883000000,
      "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      "_sd_alg": "sha-256"
    }""".trimIndent()

    assertEquals(
      setOf(
        "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
        "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
        "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
        "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
        "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsgIjlnalZ1WHRkRlJPQ2dScnROY0dVWG1GNjVyZ" +
          "GV6aV82RXJfajc2a21ZeU0iLCAgIjZ2aDlicS16UzRHS01fN0dwZ2dWYll6enU2b09HWHJtTlZHUEhQNzVVZDAiLCAgIktVUkRQ" +
          "aDRaQzE5LTN0aXotRGYzOVY4ZWlkeTFvVjNhM0gxRGEyTjBnODgiLCAgIldOOXI5ZENCSjhIVENzUzJqS0FTeFRqRXlXNW01eDY" +
          "1X1pfMnJvMmpmWE0iIF19XQ"
      ),
      sdJwt.disclosures.map { it.serialize(mapper) }.toSet()
    )
    assertEquals(
      JsonCanonicalizer(expected).encodedString,
      JsonCanonicalizer(mapper.writeValueAsString(sdJwt.issuerJwt.jwtClaimsSet.toJSONObject())).encodedString
    )
  }

  private fun getPublicKey(did: DidKey): JWK {
    val resolutionResult = DidKey.resolve(did.uri)
    return JWK.parse(resolutionResult.didDocument.assertionMethodVerificationMethodsDereferenced.first().publicKeyJwk)
  }
}

class KeyManagerSigner(private val keyManager: KeyManager, private val keyAlias: String) : ECDSAProvider(
  ECDSA.resolveAlgorithm(Curve.SECP256K1)
), JWSSigner {

  override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
    return Base64URL.encode(keyManager.sign(keyAlias, signingInput))
  }

}

class MockMapGenerator(private val values: Map<String, String> = emptyMap()) : ISaltGenerator {
  override fun generate(claim: String): String {
    return values[claim] ?: "_26bc4LT-ac6q2KI6cBW5es"
  }

}