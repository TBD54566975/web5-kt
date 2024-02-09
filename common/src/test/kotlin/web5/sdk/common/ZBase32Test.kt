package web5.sdk.common

import org.junit.jupiter.api.Test
import kotlin.test.Ignore
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
  TestVector(
    encoded = "y",
    decoded = { byteArrayOf("0".toInt(2).toByte()) }
  )
)

// todo: fix ZBase32.decode() and ZBase32.encode() so these pass.
// github issue: https://github.com/TBD54566975/tbdex-kt/issues/156
@Ignore
class ZBase32Test {
  @Test
  fun `it encodes and decodes`() {
    for (vector in zbase32Vectors) {
      val expected = byteArrayOf(0, 0)
      val actual = ZBase32.decode("yy")
      assertEquals(expected, actual)

    }
  }

  // test cases from the spec: https://github.com/tv42/zbase32/blob/main/zbase32_test.go#L16
  // spec: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
  @Test
  fun `it encodes and decodes keys`() {
    val byteArray = ByteArray(26)
    byteArray.fill(0, 0, 25)
    val byteArray2 = byteArrayOf(-11, 87, -67, 12)
    val ba1 = byteArray2 + byteArray
    assertEquals("6im54d", ZBase32.encode(ba1))

    val ba2 = byteArrayOf(0, 0)
    assertEquals("yy", ZBase32.encode(ba2))

    val ba3 = byteArrayOf()
    assertEquals("", ZBase32.encode(ba3))
  }
}