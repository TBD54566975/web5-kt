package web5.sdk.dids

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutputStreamContent
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import org.apache.commons.codec.binary.Hex
import org.erdtman.jcs.JsonCanonicalizer
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import web5.sdk.crypto.AwsKeyManager
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.dids.ion.model.PublicKey
import web5.sdk.dids.ion.model.Service
import web5.sdk.dids.ion.model.SidetreeCreateOperation
import web5.sdk.dids.ion.model.SidetreeUpdateOperation
import java.io.File
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DidIonTest {

  @Test
  @Ignore("For demonstration purposes only - this makes a network call")
  fun createWithDefault() {
    val did = DidIonManager.create(InMemoryKeyManager())
    assertContains(did.uri, "did:ion:")
    assertTrue(did.creationMetadata!!.longFormDid.startsWith(did.uri))
  }

  @Test
  @Ignore("For demonstration purposes only - relies on network and AWS configuration")
  fun `create with AWS key manager`() {
    val keyManager = AwsKeyManager()
    val ionManager = DidIonManager
    val didsCreated = buildList {
      repeat(32) {
        add(ionManager.create(keyManager))
      }
    }
    didsCreated.forEach { println(it.uri) }
  }

  @Test
  fun `invalid charset verificationMethodId throws exception`() {
    val exception = assertThrows<IllegalArgumentException> {
      DidIonManager.create(
        InMemoryKeyManager(),
        CreateDidIonOptions(
          verificationMethodId = "space is not part of the base64 url chars"
        )
      )
    }
    assertContains(exception.message!!, "is not base 64 url charset")
  }

  @Test
  fun `invalid services throw exception`() {
    class TestCase(
      val service: Service,
      val expectedContains: String
    )

    val testCases = listOf(
      TestCase(
        Service(
          id = "#dwn",
          type = "DWN",
          serviceEndpoint = "http://my.service.com",
        ),
        "is not base 64 url charse",
      ),
      TestCase(
        Service(
          id = "dwn",
          type = "really really really really really really really really long type",
          serviceEndpoint = "http://my.service.com",
        ),
        "service type \"really really really really really really really really long type\" exceeds" +
          " max allowed length of 30",
      ),
      TestCase(
        Service(
          id = "dwn",
          type = "DWN",
          serviceEndpoint = "an invalid uri",
        ),
        "service endpoint is not a valid URI",
      )
    )
    for (testCase in testCases) {
      val exception = assertThrows<IllegalArgumentException> {
        DidIonManager.create(
          InMemoryKeyManager(),
          CreateDidIonOptions(
            servicesToAdd = listOf(testCase.service)
          )
        )
      }
      assertContains(exception.message!!, testCase.expectedContains)
    }
  }

  @Test
  fun `very long verificationMethodId throws exception`() {
    val exception = assertThrows<IllegalArgumentException> {
      DidIonManager.create(
        InMemoryKeyManager(),
        CreateDidIonOptions(
          verificationMethodId = "something_thats_really_really_really_really_really_really_long"
        )
      )
    }
    assertContains(exception.message!!, "exceeds max allowed length")
  }

  @Test
  fun createWithCustom() {
    val keyManager = InMemoryKeyManager()
    val verificationKey = readKey("src/test/resources/verification_jwk.json")
    val updateKey = readKey("src/test/resources/update_jwk.json")
    val recoveryKey = readKey("src/test/resources/recovery_jwk.json")
    val manager = DidIonManager {
      ionHost = "madeuphost"
      engine = mockEngine()
    }
    val opts = CreateDidIonOptions(
      verificationPublicKey = PublicKey(
        id = verificationKey.keyID,
        type = "JsonWebKey2020",
        publicKeyJwk = verificationKey,
        purposes = listOf(PublicKeyPurpose.AUTHENTICATION),
      ),
      servicesToAdd = listOf(
        Service(
          id = "dwn",
          type = "DWN",
          serviceEndpoint = "http://hub.my-personal-server.com",
        )
      ),
      updatePublicJwk = updateKey,
      recoveryPublicJwk = recoveryKey
    )
    val did = manager.create(keyManager, opts)
    assertContains(did.uri, "did:ion:")
    assertContains(did.creationMetadata!!.longFormDid, did.creationMetadata!!.shortFormDid)
  }

  private fun readKey(pathname: String): JWK {
    return JWK.parse(
      File(pathname).readText()
    )
  }

  @Test
  fun `serializing and deserializing produces the same create operation`() {
    val jsonContent = File("src/test/resources/create_operation.json").readText()
    val expectedContent = JsonCanonicalizer(jsonContent).encodedString

    val mapper = jacksonObjectMapper()
    val createOperation = mapper.readValue<SidetreeCreateOperation>(jsonContent)

    val jsonString = mapper.writeValueAsString(createOperation)
    assertEquals(expectedContent, JsonCanonicalizer(jsonString).encodedString)
  }

  @Test
  fun `method name is ion`() {
    assertEquals("ion", DidIonManager.methodName)
  }

  @Test
  fun `create changes the key manager state`() {
    val keyManager = InMemoryKeyManager()
    val did = DidIonManager {
      engine = mockEngine()
    }.create(keyManager)
    val metadata = did.creationMetadata!!

    assertContains(did.uri, "did:ion:")
    assertContains(metadata.longFormDid, metadata.shortFormDid)
    assertDoesNotThrow {
      keyManager.getPublicKey(metadata.keyAliases.recoveryKeyAlias!!)
      keyManager.getPublicKey(metadata.keyAliases.updateKeyAlias!!)
      keyManager.getPublicKey(metadata.keyAliases.verificationKeyAlias!!)
    }
  }

  @Test
  fun `update throws exception when given invalid input`() {
    val keyManager = InMemoryKeyManager()
    val keyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val publicKey = keyManager.getPublicKey(keyAlias)

    val updateKeyAlias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)

    class TestCase(
      val services: Iterable<Service> = emptyList(),
      val publicKeys: Iterable<PublicKey> = emptyList(),
      val expected: String
    )

    val testCases = arrayOf(
      TestCase(
        services = listOf(
          Service(
            id = "#dwn",
            type = "DWN",
            serviceEndpoint = "http://my.service.com",
          )
        ),
        expected = "id \"#dwn\" is not base 64 url charset",
      ),
      TestCase(
        publicKeys = listOf(
          PublicKey(
            id = "#publicKey1",
            type = "JsonWebKey2020",
            publicKeyJwk = publicKey,
          )
        ),
        expected = "id \"#publicKey1\" is not base 64 url charset",
      ),
      TestCase(
        publicKeys = listOf(
          PublicKey(
            id = "publicKey1",
            type = "JsonWebKey2020",
            publicKeyJwk = publicKey,
          ),

          PublicKey(
            id = "publicKey1",
            type = "JsonWebKey2020",
            publicKeyJwk = publicKey,
          )
        ),
        expected = "DID Document key with ID \"publicKey1\" already exists.",
      ),
      TestCase(
        publicKeys = listOf(
          PublicKey(
            id = "publicKey1",
            type = "JsonWebKey2020",
            publicKeyJwk = publicKey,
            purposes = listOf(PublicKeyPurpose.AUTHENTICATION, PublicKeyPurpose.AUTHENTICATION)
          )
        ),
        expected = "Public key purpose \"authentication\" already specified.",
      ),
    )
    for (testCase in testCases) {
      val result = assertThrows<IllegalArgumentException> {
        DidIonManager.update(
          keyManager,
          UpdateDidIonOptions(
            didString = "did:ion:123",
            updateKeyAlias = updateKeyAlias,
            servicesToAdd = testCase.services,
            publicKeysToAdd = testCase.publicKeys,
          )
        )
      }
      assertEquals(testCase.expected, result.message)
    }
  }

  @Test
  fun `update fails when update key is absent`() {
    val result = assertThrows<IllegalArgumentException> {
      DidIonManager.update(
        InMemoryKeyManager(),
        UpdateDidIonOptions(
          didString = "did:ion:123",
          updateKeyAlias = "my_fake_key",
        )
      )
    }
    assertEquals("key with alias my_fake_key not found", result.message)
  }

  @Test
  fun `update sends the expected operation`() {
    val mapper = jacksonObjectMapper()

    val keyManager: InMemoryKeyManager = spy(InMemoryKeyManager())

    val updateKey = readKey("src/test/resources/jwkEs256k1Private.json")
    val updateKeyId = keyManager.import(updateKey)

    val nextUpdateKey = readKey("src/test/resources/jwkEs256k2Public.json")
    val nextUpdateKeyId = keyManager.import(nextUpdateKey)
    doReturn(nextUpdateKeyId).whenever(keyManager).generatePrivateKey(JWSAlgorithm.ES256K)

    val service: Service = mapper.readValue(File("src/test/resources/service1.json").readText())
    val publicKey1: PublicKey = mapper.readValue(
      File("src/test/resources/publicKeyModel1.json").readText()
    )

    val validatinMockEngine = MockEngine { request ->
      val updateOp: SidetreeUpdateOperation = mapper.readValue((request.body as OutputStreamContent).toByteArray())
      assertEquals("EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", updateOp.didSuffix)
      assertEquals("update", updateOp.type)
      assertEquals("EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ", updateOp.revealValue.toBase64Url())
      assertEquals(
        "eyJhbGciOiJFUzI1NksifQ.eyJ1cGRhdGVLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDB" +
          "leUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdh" +
          "Q004RjdrIn0sImRlbHRhSGFzaCI6IkVpQXZsbVVRYy1jaDg0Slp5bmdQdkJzUkc3eWh4aUFSenlYOE5lNFQ4LTlyTncifQ." +
          "Q9MuoQqFlhYhuLDgx4f-0UM9QyCfZp_cXt7vnQ4ict5P4_ZWKwG4OXxxqFvdzE-e3ZkEbvfR0YxEIpYO9MrPFw",
        updateOp.signedData
      )
      assertEquals("EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA", updateOp.delta.updateCommitment.toBase64Url())
      assertEquals(4, updateOp.delta.patches.count())
      respond(
        content = ByteReadChannel("""{"hello":"world"}"""),
        headers = headersOf(HttpHeaders.ContentType, "application/json"),
        status = HttpStatusCode.OK,
      )
    }
    val updateMetadata = DidIonManager {
      engine = validatinMockEngine
    }.update(
      keyManager,
      UpdateDidIonOptions(
        didString = "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        updateKeyAlias = updateKeyId,
        servicesToAdd = listOf(service),
        idsOfServicesToRemove = setOf("someId1"),
        publicKeysToAdd = listOf(publicKey1),
        idsOfPublicKeysToRemove = setOf("someId2"),
      ),
    )

    assertTrue(updateMetadata.updateKeyAlias.isNotEmpty())
    assertEquals("""{"hello":"world"}""", updateMetadata.operationsResponseBody)
  }

  @Test
  fun `recover operation is the expected one`() {
    val mapper = jacksonObjectMapper()

    val publicKey1: PublicKey = mapper.readValue(
      File("src/test/resources/publicKeyModel1.json").readText()
    )
    val service: Service = mapper.readValue(File("src/test/resources/service1.json").readText())

    val keyManager = spy(InMemoryKeyManager())
    val recoveryKey = readKey("src/test/resources/jwkEs256k1Private.json")
    val recoveryKeyAlias = keyManager.import(recoveryKey)

    val nextRecoveryKey = readKey("src/test/resources/jwkEs256k2Public.json")
    val nextRecoveryKeyId = keyManager.import(nextRecoveryKey)

    val nextUpdateKey = readKey("src/test/resources/jwkEs256k3Public.json")
    val nextUpdateKeyId = keyManager.import(nextUpdateKey)

    doReturn(nextRecoveryKeyId, nextUpdateKeyId).whenever(keyManager).generatePrivateKey(JWSAlgorithm.ES256K)

    val (recoverOperation, keyAliases) = DidIonManager.createRecoverOperation(
      keyManager,
      RecoverDidIonOptions(
        did = "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        recoveryKeyAlias = recoveryKeyAlias,
        verificationPublicKey = publicKey1,
        servicesToAdd = listOf(service),
      )
    )

    assertEquals("EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", recoverOperation.didSuffix)
    assertEquals("EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ", recoverOperation.revealValue.toBase64Url())
    assertEquals("recover", recoverOperation.type)
    assertEquals(
      "EiBJGXo0XUiqZQy0r-fQUHKS3RRVXw5nwUpqGVXEGuTs-g",
      recoverOperation.delta.updateCommitment.toBase64Url()
    )
    assertEquals(
      "eyJhbGciOiJFUzI1NksifQ.eyJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaURLSWt3cU82OUlQRzNwT2xIa2RiODZuWXQwYU54U" +
        "0hadTJyLWJoRXpuamRBIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJT" +
        "WGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ00" +
        "4RjdrIn0sImRlbHRhSGFzaCI6IkVpQm9HNlFtamlTSm5ON2phaldnaV9vZDhjR3dYSm9Nc2RlWGlWWTc3NXZ2SkEifQ.58n6Fel9DmR" +
        "AXxwcJMUwYaUhmj5kigKMNrGjr7eJaJcjOmjvwlKLSjiovWiYrb9yjkfMAjpgbAdU_2EDI1_lZw",
      recoverOperation.signedData
    )
    assertEquals(1, recoverOperation.delta.patches.count())
    assertEquals(nextUpdateKeyId, keyAliases.updateKeyAlias)
    assertEquals(nextRecoveryKeyId, keyAliases.recoveryKeyAlias)
  }

  @Test
  fun `recover creates keys in key manager`() {
    val ionManager = DidIonManager {
      engine = mockEngine()
    }
    val keyManager = spy(InMemoryKeyManager())
    val did = ionManager.create(keyManager)
    assertNotNull(did.creationMetadata)
    val recoveryKeyAlias = did.creationMetadata!!.keyAliases.verificationKeyAlias

    assertNotNull(recoveryKeyAlias)
    // Imagine that your update key was compromised, so you need to recover your DID.
    val opts = RecoverDidIonOptions(
      did = did.uri,
      recoveryKeyAlias = recoveryKeyAlias,
    )
    val recoverResult = ionManager.recover(keyManager, opts)
    assertNotNull(recoverResult.keyAliases.updateKeyAlias)
    assertNotNull(recoverResult.keyAliases.recoveryKeyAlias)
    assertNotNull(recoverResult.keyAliases.verificationKeyAlias)

    assertDoesNotThrow {
      keyManager.getPublicKey(recoverResult.keyAliases.updateKeyAlias!!)
      keyManager.getPublicKey(recoverResult.keyAliases.recoveryKeyAlias!!)
      keyManager.getPublicKey(recoverResult.keyAliases.verificationKeyAlias!!)
    }
    assertEquals("{}", recoverResult.operationsResponse)
    assertNotEquals(recoveryKeyAlias, recoverResult.keyAliases.recoveryKeyAlias)
  }

  @Test
  fun `deactivate operation is the expected one`() {
    val keyManager = InMemoryKeyManager()
    val recoveryKey = readKey("src/test/resources/jwkEs256k1Private.json")
    val recoveryKeyAlias = keyManager.import(recoveryKey)

    val deactivateResult = DidIonManager {
      engine = mockEngine()
    }.deactivate(
      keyManager,
      DeactivateDidIonOptions(
        did = "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        recoveryKeyAlias = recoveryKeyAlias,
      )
    )

    val deactivateOperation = deactivateResult.deactivateOperation
    assertEquals("EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", deactivateOperation.didSuffix)
    assertEquals("deactivate", deactivateOperation.type)
    assertEquals(
      "EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ",
      deactivateOperation.revealValue.toBase64Url()
    )
    assertEquals(
      "eyJhbGciOiJFUzI1NksifQ.eyJkaWRTdWZmaXgiOiJFaUR5T1FiYlpBYTNhaVJ6ZUNrVjdMT3gzU0VSampIOTNFWG9JTTNVb040b1" +
        "dnIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaH" +
        "dDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn19.uLgnDBmmFzST4VTmd" +
        "JcmFKVicF0kQaBqEnRQLbqJydgIg_2oreihCA5sBBIUBlSXwvnA9xdK97ksJGmPQ7asPQ",
      deactivateOperation.signedData
    )
  }

  @Test
  fun `bad request throws exception`() {
    val exception = assertThrows<InvalidStatusException> {
      DidIonManager {
        engine = badRequestMockEngine()
      }.resolve("did:ion:foobar")
    }

    assertEquals(HttpStatusCode.BadRequest.value, exception.statusCode)
  }

  @Test
  fun `multihash test vector`() {
    // test vector taken from: https://multiformats.io/multihash/#sha2-256---256-bits-aka-sha256
    val input = "Merkle–Damgård".toByteArray()

    val mhBytes = multihash(input)
    val mhHex = Hex.encodeHexString(mhBytes)
    assertEquals("122041dd7b6443542e75701aa98a0c235951a28a0d851b11564d20022ab11d2589a8", mhHex)
  }

  private fun badRequestMockEngine() = MockEngine {
    respond(
      content = ByteReadChannel("""{}"""),
      status = HttpStatusCode.BadRequest,
      headers = headersOf(HttpHeaders.ContentType, "application/json")
    )
  }

  private fun mockEngine() = MockEngine { request ->
    when (request.url.encodedPath) {
      "/operations" -> {
        respond(
          content = ByteReadChannel("""{}"""),
          status = HttpStatusCode.OK,
          headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
      }

      else -> respond(
        content = ByteReadChannel(File("src/test/resources/basic_did_resolution.json").readText()),
        status = HttpStatusCode.OK,
        headers = headersOf(HttpHeaders.ContentType, "application/json")
      )
    }
  }
}