package web5.sdk.common

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import org.junit.jupiter.api.Test
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.LocalKeyManager
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

val zbase32Vectors = listOf(
  TestVector(
    encoded = "pb1sa5dx",
    decoded = { "hello".toByteArray() }
  ),
  TestVector(
    encoded = "pb1sa5dxrb5s6huccooo",
    decoded = { "hello world!".toByteArray() }
  ),
  TestVector(
    encoded = "ktwgkedtqiwsg43ycj3g675qrbug66bypj4s4hdurbzzc3m1rb4go3jyptozw6jyctzsqmo",
    decoded = { "The quick brown fox jumps over the lazy dog.".toByteArray() }
  ),
)

class ZBase32Test {
  @Test
  fun `it encodes and decodes`() {
    for (vector in zbase32Vectors) {
      val encoded = ZBase32.encode(vector.decoded())
      assertEquals(vector.encoded, encoded)

      val decoded = ZBase32.decode(encoded)
      assertContentEquals(vector.decoded(), decoded)
    }
  }

  @Test
  fun `it encodes and decodes keys`() {
    val manager = LocalKeyManager()

    for (i in 0..50) {
      val keyAlias = manager.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
      val pubKeyJwk = manager.getPublicKey(keyAlias)
      val pubKeyBytes = Crypto.publicKeyToBytes(pubKeyJwk)
      val encodedPubKey = ZBase32.encode(pubKeyBytes)
      val decodedPubKey = ZBase32.decode(encodedPubKey)
      assertContentEquals(pubKeyBytes, decodedPubKey)
    }
  }
}