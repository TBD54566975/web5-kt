package web5.sdk.crypto

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.apache.commons.codec.binary.Hex
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.common.Convert
import web5.sdk.common.Json
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.testing.TestVectors
import java.io.File
import java.security.SignatureException
import java.util.Random
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Secp256k1Test {
  @Test
  fun `test key generation`() {
    val privateKey = Secp256k1.generatePrivateKey()

    Secp256k1.validateKey(privateKey)
    assertEquals(Jwa.ES256K.name, privateKey.alg)
    assertEquals("sig", privateKey.use)
    assertNotNull(privateKey.kid)
    assertTrue(privateKey.kty == "EC")
    assertNotNull(privateKey.d)
  }

  @Test
  fun `test public key`() {
    val privateKey = Secp256k1.generatePrivateKey()

    val publicKey = Secp256k1.computePublicKey(privateKey)

    Secp256k1.validateKey(publicKey)
    assertEquals(publicKey.kid, privateKey.kid)
    assertEquals(Jwa.ES256K.name, publicKey.alg)
    assertEquals("sign", publicKey.use)
    assertTrue(publicKey.kty == "EC")
    assertNotNull(publicKey.d)
  }

  @Test
  fun `signing the same payload with the same key should produce the same signature`() {
    val privateKey = Secp256k1.generatePrivateKey()
    val publicKey = Secp256k1.computePublicKey(privateKey)
    val payload = "hello".toByteArray()

    val sig1 = Secp256k1.sign(privateKey, payload)
    Secp256k1.verify(publicKey, payload, sig1)

    val sig2 = Secp256k1.sign(privateKey, payload)
    Secp256k1.verify(publicKey, payload, sig2)

    val base64UrlEncodedSig1 = Convert(sig1).toBase64Url()
    val base64UrlEncodedSig2 = Convert(sig2).toBase64Url()

    assertEquals(base64UrlEncodedSig1, base64UrlEncodedSig2)
  }

  @Test
  fun `pressure test signature verification`() {
    // TODO: consider using the same private key
    val privateKey = Secp256k1.generatePrivateKey()
    val publicKey = Secp256k1.computePublicKey(privateKey)

    repeat(10_000) {
      // generate a payload of up to 100 random bytes
      val payloadSize = Random().nextInt(100) + 1
      val payload = ByteArray(payloadSize)
      Random().nextBytes(payload)

      try {
        val sig1 = Secp256k1.sign(privateKey, payload)
        Secp256k1.verify(publicKey, payload, sig1)
      } catch (e: SignatureException) {
        val payloadString = Convert(payload).toBase64Url()
        println("($it) $e. Payload (base64url encoded): $payloadString")
        throw e
      }
    }
  }
}

class Web5TestVectorsCryptoEs256k {
  data class SignTestInput(
    val data: String,
    val key: Map<String, Any>?,
  )

  data class VerifyTestInput(
    val data: String,
    val key: Map<String, Any>?,
    val signature: String,
  )

  private val mapper = jacksonObjectMapper()

  @Test
  fun sign() {
    val typeRef = object : TypeReference<TestVectors<SignTestInput, String>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/crypto_es256k/sign.json"), typeRef)

    testVectors.vectors.filter { it.errors == false }.forEach { vector ->
      val inputByteArray: ByteArray = Hex.decodeHex(vector.input.data.toCharArray())
      val jwkMap = vector.input.key
      val ecJwk = Json.parse<Jwk>(jwkMap.toString())
      val signedByteArray: ByteArray = Secp256k1.sign(ecJwk, inputByteArray)

      val signedHex = Hex.encodeHexString(signedByteArray)

      assertEquals(vector.output, signedHex)
    }

    testVectors.vectors.filter { it.errors == true }.forEach { vector ->
      assertFails {
        val inputByteArray: ByteArray = Hex.decodeHex(vector.input.data.toCharArray())
        val jwkMap = vector.input.key

        val ecJwk = Json.parse<Jwk>(jwkMap.toString())

        Secp256k1.sign(ecJwk, inputByteArray)
      }
    }
  }

  @Test
  fun verify() {
    val typeRef = object : TypeReference<TestVectors<VerifyTestInput, Boolean>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/crypto_es256k/verify.json"), typeRef)

    testVectors.vectors.filter { it.errors == false }.forEach { vector ->
      val inputByteArray: ByteArray = Hex.decodeHex(vector.input.data.toCharArray())
      val jwkMap = vector.input.key
      val signatureByteArray = Hex.decodeHex(vector.input.signature.toCharArray())

      val ecJwk = Json.parse<Jwk>(jwkMap.toString())

      if (vector.output == true) {
        assertDoesNotThrow { Secp256k1.verify(ecJwk, inputByteArray, signatureByteArray) }
      } else {
        assertFails { Secp256k1.verify(ecJwk, inputByteArray, signatureByteArray) }
      }
    }

    testVectors.vectors.filter { it.errors == true }.forEach { vector ->
      assertFails {
        val inputByteArray: ByteArray = Hex.decodeHex(vector.input.data.toCharArray())
        val jwkMap = vector.input.key
        val signatureByteArray = Hex.decodeHex(vector.input.signature.toCharArray())

        val ecJwk = Json.parse<Jwk>(jwkMap.toString())
        Secp256k1.verify(ecJwk, inputByteArray, signatureByteArray)
      }
    }
  }
}