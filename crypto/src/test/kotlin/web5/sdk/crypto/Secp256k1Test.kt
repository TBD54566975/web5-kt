package web5.sdk.crypto

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import org.junit.jupiter.api.Test
import web5.sdk.common.Convert
import java.security.SignatureException
import java.util.Random
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Secp256k1Test {
  @Test
  fun `test key generation`() {
    val privateKey = Secp256k1.generatePrivateKey()

    Secp256k1.validateKey(privateKey)
    assertEquals(JWSAlgorithm.ES256K, privateKey.algorithm)
    assertEquals(KeyUse.SIGNATURE, privateKey.keyUse)
    assertNotNull(privateKey.keyID)
    assertEquals(KeyType.EC, privateKey.keyType)
    assertTrue(privateKey.isPrivate)
  }

  @Test
  fun `test public key`() {
    val privateKey = Secp256k1.generatePrivateKey()

    val publicKey = Secp256k1.computePublicKey(privateKey)

    Secp256k1.validateKey(publicKey)
    assertEquals(publicKey.keyID, privateKey.keyID)
    assertEquals(JWSAlgorithm.ES256K, publicKey.algorithm)
    assertEquals(KeyUse.SIGNATURE, publicKey.keyUse)
    assertEquals(KeyType.EC, publicKey.keyType)
    assertFalse(publicKey.isPrivate)
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

    val base64UrlEncodedSig1 = Convert(sig1).toBase64Url(padding = false)
    val base64UrlEncodedSig2 = Convert(sig2).toBase64Url(padding = false)

    assertEquals(base64UrlEncodedSig1, base64UrlEncodedSig2)
  }

  @Test
  fun `pressure test signature verification`() {
    // TODO: consider using the same private key
    val privateKey = Secp256k1.generatePrivateKey()
    val publicKey = Secp256k1.computePublicKey(privateKey)

    repeat(10_000) {
      // generate a payload of up to 100 random bytes
      val payloadSize = Random().nextInt(1, 100)
      val payload = ByteArray(payloadSize)
      Random().nextBytes(payload)

      try {
        val sig1 = Secp256k1.sign(privateKey, payload)
        Secp256k1.verify(publicKey, payload, sig1)
      } catch (e: SignatureException) {
        val payloadString = Convert(payload).toBase64Url(false)
        println("($it) $e. Payload (base64url encoded): $payloadString")
        throw e
      }
    }
  }
}