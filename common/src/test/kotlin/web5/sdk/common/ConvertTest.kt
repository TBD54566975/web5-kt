package web5.sdk.common

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.Ignore
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ConvertTest {
  @Nested
  inner class StringTest {
    inner class TestCase(
      val input: Any,
      val encodingFormat: EncodingFormat? = null,
      val expectedOutput: Any? = null
    )

    @Test
    fun toBase64Url() {

      val testCases = listOf(
        TestCase("foo", null, "Zm9v"),
        TestCase("foo", EncodingFormat.Base64Url, "foo")
      )

      for (testCase in testCases) {
        val output = Convert(testCase.input, testCase.encodingFormat).toBase64Url()
        assertEquals(testCase.expectedOutput, output)
      }
    }

    @Test
    fun toBase64Url_FailCases() {

      val testCases = listOf(
        TestCase("foo", EncodingFormat.Base58Btc),
        TestCase(1)
      )

      for (testCase in testCases) {
        assertFailsWith<UnsupportedOperationException> {
          Convert(testCase.input, testCase.encodingFormat).toBase64Url()
        }
      }
    }

    @Test
    fun toBase58Btc() {

      val testCases = listOf(
        TestCase("foo", EncodingFormat.Base58Btc, "foo"),
        TestCase("foo", EncodingFormat.Base64Url, "AdX"),
        TestCase("bar", EncodingFormat.ZBase32, "F"),
        TestCase("foo", null, "bQbp")
        )

      for (testCase in testCases) {
        val output = Convert(testCase.input, testCase.encodingFormat).toBase58Btc()
        assertEquals(testCase.expectedOutput, output)
      }
    }

    @Test
    fun toBase58Btc_FailCases() {

      val testCases = listOf(
        TestCase(1)
      )

      for (testCase in testCases) {
        assertFailsWith<UnsupportedOperationException> {
          Convert(testCase.input, testCase.encodingFormat).toBase58Btc()
        }
      }
    }

    // todo: fix ZBase32.decode() and ZBase32.encode() so this passes.
    // github issue: https://github.com/TBD54566975/tbdex-kt/issues/156
    @Ignore
    @Test
    fun toZBase32() {

      val testCases = listOf(
        TestCase("foo", EncodingFormat.Base58Btc, "y869r"),
        TestCase("foo", EncodingFormat.Base64Url, "x4fy"),
        TestCase("foo", EncodingFormat.ZBase32, "foo"),
        TestCase("foo", null, "c3zs6")
        )

      for (testCase in testCases) {
        val output = Convert(testCase.input, testCase.encodingFormat).toZBase32()
        assertEquals(testCase.expectedOutput, output)
      }
    }

    @Test
    fun toZBase32_FailCases() {

      val testCases = listOf(
        TestCase(1)
      )

      for (testCase in testCases) {
        assertFailsWith<UnsupportedOperationException> {
          Convert(testCase.input, testCase.encodingFormat).toZBase32()
        }
      }
    }

    @Test
    fun toStr() {

      val testCases = listOf(
        TestCase("Zm9v", EncodingFormat.Base64Url, "foo"),
        TestCase("c3zs6", EncodingFormat.ZBase32, "foo"),
        TestCase("foo", null, "foo")
        )

      for (testCase in testCases) {
        val output = Convert(testCase.input, testCase.encodingFormat).toStr()
        assertEquals(testCase.expectedOutput, output)
      }
    }

    @Test
    fun toStr_FailCases() {

      val testCases = listOf(
        TestCase("foo", EncodingFormat.Base58Btc),
        TestCase(1)
      )

      for (testCase in testCases) {
        assertFailsWith<UnsupportedOperationException> {
          Convert(testCase.input, testCase.encodingFormat).toStr()
        }
      }
    }

    @Test
    fun toByteArray() {

      val testCases = listOf(
        TestCase("bQbp", EncodingFormat.Base58Btc, "foo".toByteArray()),
        TestCase("Zm9v", EncodingFormat.Base64Url, "foo".toByteArray()),
        TestCase("c3zs6", EncodingFormat.ZBase32, "foo".toByteArray()),
        TestCase("foo".toByteArray(), null, "foo".toByteArray())
      )

      for (testCase in testCases) {
        val output = Convert(testCase.input, testCase.encodingFormat).toByteArray()
        assertArrayEquals(testCase.expectedOutput as ByteArray, output)
      }
    }

    @Test
    fun toByteArray_FailCases() {

      val testCases = listOf(
        TestCase(1)
      )

      for (testCase in testCases) {
        assertFailsWith<UnsupportedOperationException> {
          Convert(testCase.input, testCase.encodingFormat).toByteArray()
        }
      }
    }
  }
}