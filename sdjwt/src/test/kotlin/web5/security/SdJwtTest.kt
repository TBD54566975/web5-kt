package web5.security

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.impl.ECDSAProvider
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.methods.key.DidKey
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

  @Test
  fun `whole flow from issuer to holder to verifier`() {
    // First issue an SD-JWT
    val blinder = SdJwtBlinder()

    val claimsData = """{      
      "given_name": "Mister",
      "family_name": "Tee",
      "birthdate": "1940-10-31",
      "nationalities": ["US", "DE", "PO"],
      "address": {
        "street": "happy street 123",
        "zip_code": "12345"
      }
    }""".trimIndent()
    val claimsToBlind = mapOf(
      "given_name" to FlatBlindOption,
      "family_name" to FlatBlindOption,
      "birthdate" to FlatBlindOption,
      "nationalities" to ArrayBlindOption,
      "address" to SubClaimBlindOption(
        mapOf(
          "street" to FlatBlindOption,
          "zip_code" to FlatBlindOption,
        )
      ),
    )
    val builder = blinder.blind(
      claimsData,
      claimsToBlind = claimsToBlind
    )
    val jwsAlgorithm = JWSAlgorithm.ES256K

    val keyManager = InMemoryKeyManager()
    val did = DidKey.create(keyManager)
    val issuerPublicJwk = getPublicKey(did)
    val alias = keyManager.getDeterministicAlias(issuerPublicJwk)
    val issuerSigner = KeyManagerSigner(keyManager, alias)

    builder.issuerHeader = JWSHeader.Builder(jwsAlgorithm)
      .type(JOSEObjectType.JWT)
      .keyID(alias)
      .build()
    val sdJwt = builder.build()

    sdJwt.signAsIssuer(issuerSigner)
    val serializedSdJwt = sdJwt.serialize()

    // Phew! That was quite a bit of work. Now let's assume that this got to the holder.
    // The holder only wants to reveal their birthdate, a couple of nationalities, and only the zip_code.
    val holderSdJwt = SdJwt.parse(serializedSdJwt)

    val idsOfDisclosures: Set<Int> = holderSdJwt.selectDisclosures(
      setOf(
        holderSdJwt.digestsOf("birthdate"),
        holderSdJwt.digestsOf("nationalities", "PO"),
        holderSdJwt.digestsOf("nationalities", "US"),
        holderSdJwt.digestsOf("address"),
        holderSdJwt.digestsOf("zip_code"),
      ).filterNotNull().toSet()
    )
    val sdJwtToPresent = SdJwt(
      issuerJwt = holderSdJwt.issuerJwt,
      disclosures = holderSdJwt.disclosures.filterIndexed { index, _ -> idsOfDisclosures.contains(index) },
    )
    val serializedPresentedSdJwt = sdJwtToPresent.serialize()

    // Optionally, the holder can choose to sign key binding stuff, but we're skipping that step.

    // Now the verifier wants to make sure stuff looks ok.
    val receivedSdJwt = SdJwt.parse(serializedPresentedSdJwt)
    // ... make sure you always verify!
    receivedSdJwt.verify(
      VerificationOptions(
        issuerPublicJwk = issuerPublicJwk,
        supportedAlgorithms = setOf(JWSAlgorithm.ES256K),
        holderBindingOption = HolderBindingOption.SkipVerifyHolderBinding,
      )
    )


    //... and then you can process the received information.
    val claimSet = receivedSdJwt.unblind()

    // the verifier only received birthdate!
    assertEquals(
      mapOf(
        "birthdate" to "1940-10-31",
        "nationalities" to listOf("US", "PO"),
        "address" to mapOf(
          "zip_code" to "12345"
        )
      ),
      claimSet.toJSONObject(),
    )
  }

  private fun getPublicKey(did: DidKey): JWK {
    val resolutionResult = DidKey.resolve(did.uri)
    return JWK.parse(resolutionResult.didDocument.assertionMethodVerificationMethodsDereferenced.first().publicKeyJwk)
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

class KeyManagerSigner(private val keyManager: KeyManager, private val keyAlias: String) : ECDSAProvider(
  JWSAlgorithm.ES256K
), JWSSigner {

  override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
    return Base64URL.encode(keyManager.sign(keyAlias, signingInput))
  }

}