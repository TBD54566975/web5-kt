package web5.sdk.crypto

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import web5.sdk.common.Json
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.testing.TestVectors
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFails

class Web5TestVectorsCryptoEd25519 {
  data class VerifyTestInput(
    val key: Map<String, Any>,
    val signature: String,
    val data: String
  )

  data class SignTestInput(
    val key: Map<String, Any>,
    val data: String
  )

  private val mapper = jacksonObjectMapper()

  @Test
  fun sign() {
    val typeRef = object : TypeReference<TestVectors<SignTestInput, String>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/crypto_ed25519/sign.json"), typeRef)

    testVectors.vectors.filter { it.errors == false }.forEach { vector ->
      // Convert input data from hex to byte array
      val inputByteArray: ByteArray = hexStringToByteArray(vector.input.data)
      val jwkMap = vector.input.key

      val ed25519Jwk = Json.parse<Jwk>(Json.stringify(jwkMap))

      val signedByteArray: ByteArray = Ed25519.sign(ed25519Jwk, inputByteArray)

      // Convert signed byte array to hex string for comparison
      val signedHex = byteArrayToHexString(signedByteArray)

      assertEquals(vector.output, signedHex)
    }

    testVectors.vectors.filter { it.errors == true }.forEach { vector ->
      assertFails {
        // Convert input data from hex to byte array
        val inputByteArray: ByteArray = hexStringToByteArray(vector.input.data)
        val jwkMap = vector.input.key

        val ed25519Jwk = Json.parse<Jwk>(jwkMap.toString())

        Ed25519.sign(ed25519Jwk, inputByteArray)
      }
    }
  }

  @Test
  fun verify() {
    val typeRef = object : TypeReference<TestVectors<VerifyTestInput, Boolean>>() {}
    val testVectors = mapper.readValue(File("../web5-spec/test-vectors/crypto_ed25519/verify.json"), typeRef)

    testVectors.vectors.filter { it.errors == false }.forEach { vector ->
      val key = Json.parse<Jwk>(Json.stringify(vector.input.key))
      val data = hexStringToByteArray(vector.input.data)
      val signature = hexStringToByteArray(vector.input.signature)
      if (vector.output == true) {
        assertDoesNotThrow {
          Ed25519.verify(key, data, signature)
        }
      } else {
        assertFails {
          Ed25519.verify(key, data, signature)
        }
      }
    }

    testVectors.vectors.filter { it.errors == true }.forEach { vector ->
      assertFails {
        val key = Json.parse<Jwk>(vector.input.key.toString())
        val data = hexStringToByteArray(vector.input.data)
        val signature = hexStringToByteArray(vector.input.signature)
        Ed25519.verify(key, data, signature)
      }
    }

  }

  // Utility function to convert hex string to byte array
  private fun hexStringToByteArray(s: String): ByteArray {
    val len = s.length
    val data = ByteArray(len / 2)
    for (i in 0 until len step 2) {
      data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
    }
    return data
  }

  // Utility function to convert byte array to hex string
  private fun byteArrayToHexString(bytes: ByteArray): String {
    return bytes.joinToString("") { "%02x".format(it) }
  }
}