package web5.sdk.common

import org.junit.jupiter.api.Test
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
//    val manager = InMemoryKeyManager()
//    val publicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
//    val publicKeyBytes = Convert(publicKey, EncodingFormat.Base64Url).toByteArray()
//
//    val encodedPubKey = ZBase32.encode(publicKeyBytes)
//    val decodedPubKey = ZBase32.decode(encodedPubKey)
//    assertContentEquals(pubKeyBytes, decodedPubKey)

//    {245, 87, 189, 12}
    val byteArray = ByteArray(26)
    byteArray.fill(0, 0, 25)
    val byteArray2 = byteArrayOf(-11, 87, -67, 12)
    val finalByteArray = byteArray2 + byteArray
    println(finalByteArray.size)

    val ba2 = byteArrayOf(0, 0)
    println(ZBase32.encode(ba2))
  }
}