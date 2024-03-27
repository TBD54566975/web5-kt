package web5.sdk.dids.did

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.junit.jupiter.api.Test
import web5.sdk.common.Json
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.didcore.DidDocument
import web5.sdk.testing.TestVectors
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFails

class Web5TestVectorsPortableDid {

  data class CreateTestInput(
    val uri: String?,
    val privateKeys: List<Jwk>?,
    val document: DidDocument?,
    val metadata: Map<String, Any>?,
  )


  private val mapper = jacksonObjectMapper()

  @Test
  fun create() {
    val typeRef = object : TypeReference<TestVectors<CreateTestInput, String>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/portable_did/parse.json"), typeRef)

    testVectors.vectors.filter { it.errors == false }.forEach { vector ->

      val portableDid = Json.parse<PortableDid>(Json.stringify(mapOf(
        "uri" to vector.input.uri,
        "privateKeys" to vector.input.privateKeys,
        "document" to vector.input.document,
        "metadata" to vector.input.metadata
      )))

      val bearerDid = BearerDid.import(portableDid, InMemoryKeyManager())
      val did = Did.parse(vector.input.uri!!)
      assertEquals(bearerDid.uri, vector.input.uri)
      assertEquals(bearerDid.document.toString(), vector.input.document.toString())
      assertEquals(bearerDid.did.url, did.url)
    }

    testVectors.vectors.filter { it.errors == true }.forEach { vector ->
      assertFails(vector.description) {
        Json.parse<PortableDid>(Json.stringify(mapOf(
          "uri" to vector.input.uri,
          "privateKeys" to vector.input.privateKeys,
          "document" to vector.input.document,
          "metadata" to vector.input.metadata
        )))
      }
    }
  }

}

class PortableDidTest {
}